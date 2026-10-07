"""FastAPI backend — Option A (in-process model). Single container demo."""
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()  # loads .env at repo root (GEMINI_API_KEY, DATABASE_URL, MODEL_PATH)

from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session

from database.db import init_db, SessionLocal
from database import repository as repo
from api.schemas import FlowIn, PredictOut, AnomalyOut, IngestOut, InvestigationOut, EvidenceOut, ReportOut
from features.flow_features import extract_features
from ml.predict import get_detector
from events.threshold import load_thresholds
from events.event_manager import build_event
from capture.normalizer import normalize
from agent.stub_agent import run_stub_investigation
from reports.generator import build_report, new_report_doc

_detector = None
_thresholds = {"investigate_at": 0.85, "monitor_at": 0.60}


def _get_detector():
    global _detector
    if _detector is None:
        init_db()
        _detector = get_detector()
    return _detector


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _thresholds
    init_db()
    _get_detector()
    _thresholds = load_thresholds()
    from llm import synthesizer as _llm

    print(f"[api] detector={_detector.model_name}:{_detector.model_version} thresholds={_thresholds}")
    print(f"[api] llm_enabled={_llm.enabled()} model={_llm.model_name()} key_set={bool(os.getenv('GEMINI_API_KEY'))}")
    yield


app = FastAPI(title="NetSentry AI backend", version="0.1.0", lifespan=lifespan)


def get_db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


@app.get("/health")
def health():
    from llm import synthesizer as _llm

    d = _get_detector()
    return {"status": "ok", "model": getattr(d, "model_version", "unloaded"), "llm_enabled": _llm.enabled(), "llm_model": _llm.model_name()}


@app.post("/flows/ingest", response_model=IngestOut)
def ingest_flow(flow: FlowIn, db: Session = Depends(get_db)):
    det = _get_detector()
    raw = normalize(flow.model_dump(exclude_none=False), 0)
    if not raw["flow_id"]:
        raw["flow_id"] = f"FLOW-{uuid.uuid4().hex[:8].upper()}"
    if not raw.get("timestamp"):
        raw["timestamp"] = datetime.now(timezone.utc)
    feats = extract_features(raw, {})
    res = det.predict(feats)
    raw["features"] = feats
    repo.upsert_flow(db, raw)
    event = build_event(raw["flow_id"], res.anomaly_score, res.model_version, _thresholds)
    event_id = None
    if event:
        repo.create_event(db, event)
        event_id = event["event_id"]
    return IngestOut(flow_id=raw["flow_id"], anomaly_score=res.anomaly_score, prediction=res.prediction, event_id=event_id)


@app.get("/flows")
def get_flows(limit: int = 50, offset: int = 0, src_ip: str | None = None, db: Session = Depends(get_db)):
    rows = repo.list_flows(db, limit=limit, offset=offset, src_ip=src_ip)
    return [
        {"flow_id": r.flow_id, "src_ip": r.src_ip, "dst_ip": r.dst_ip, "dst_port": r.dst_port, "protocol": r.protocol, "features": r.features}
        for r in rows
    ]


@app.get("/anomalies", response_model=list[AnomalyOut])
def get_anomalies(limit: int = Query(default=50, le=500), status: str | None = None, min_score: float | None = None, db: Session = Depends(get_db)):
    rows = repo.list_events(db, limit=limit, status=status, min_score=min_score)
    return [AnomalyOut(event_id=r.event_id, flow_id=r.flow_id, anomaly_score=r.anomaly_score, model_version=r.model_version, status=r.status, created_at=r.created_at) for r in rows]


@app.get("/anomalies/{event_id}", response_model=AnomalyOut)
def get_anomaly(event_id: str, db: Session = Depends(get_db)):
    r = repo.get_event(db, event_id)
    if not r:
        from fastapi import HTTPException

        raise HTTPException(404, "event not found")
    return AnomalyOut(event_id=r.event_id, flow_id=r.flow_id, anomaly_score=r.anomaly_score, model_version=r.model_version, status=r.status, created_at=r.created_at)


@app.post("/model/predict", response_model=PredictOut)
def model_predict(flow: FlowIn):
    det = _get_detector()
    raw = normalize(flow.model_dump(), 0)
    feats = extract_features(raw, {})
    res = det.predict(feats)
    return PredictOut(flow_id=raw.get("flow_id") or "FLOW-TEST", model=res.model, model_version=res.model_version, anomaly_score=res.anomaly_score, prediction=res.prediction, features_used=res.features_used)


@app.post("/investigations/{event_id}", response_model=InvestigationOut)
def start_investigation(event_id: str, db: Session = Depends(get_db)):
    """Phase 1: deterministic stub (3 tools). Phase 2: LangGraph replaces run_stub_investigation internals."""
    from fastapi import HTTPException

    if not repo.get_event(db, event_id):
        raise HTTPException(404, "event not found")
    inv_id = run_stub_investigation(db, event_id)
    # Auto-build stub report so dashboard has full chain immediately
    inv = repo.get_investigation(db, inv_id)
    ev = repo.get_event(db, event_id)
    ev_rows = repo.list_evidence(db, inv_id)
    rep_json = build_report(
        {"event_id": ev.event_id, "flow_id": ev.flow_id, "anomaly_score": ev.anomaly_score, "model_version": ev.model_version},
        [{"source_tool": e.source_tool, "payload": e.payload} for e in ev_rows],
    )
    # Optional LLM enhancement (quota-safe: stub kept on any failure/off)
    try:
        from llm.synthesizer import synthesize

        llm_out = synthesize(
            {"event_id": ev.event_id, "anomaly_score": ev.anomaly_score},
            [{"source_tool": e.source_tool, "payload": e.payload} for e in ev_rows],
        )
        if llm_out:
            rep_json["findings"] = llm_out.get("findings") or rep_json["findings"]
            rep_json["confidence"] = llm_out.get("confidence", rep_json["confidence"])
            rep_json["uncertainties"] = llm_out.get("uncertainties", rep_json["uncertainties"])
            rep_json["llm_model"] = os.getenv("GEMINI_MODEL", "gemini-2.0-flash-lite")
    except Exception as e:
        print(f"[api] llm enhance skipped: {e}")
    repo.save_report(db, new_report_doc(inv_id, rep_json))
    return InvestigationOut(investigation_id=inv.investigation_id, event_id=inv.event_id, state=inv.state, started_at=inv.started_at, completed_at=inv.completed_at, outcome=inv.outcome)


@app.get("/investigations/{investigation_id}", response_model=InvestigationOut)
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    from fastapi import HTTPException

    r = repo.get_investigation(db, investigation_id)
    if not r:
        raise HTTPException(404, "investigation not found")
    return InvestigationOut(investigation_id=r.investigation_id, event_id=r.event_id, state=r.state, started_at=r.started_at, completed_at=r.completed_at, outcome=r.outcome)


@app.get("/investigations/{investigation_id}/evidence", response_model=list[EvidenceOut])
def get_evidence(investigation_id: str, db: Session = Depends(get_db)):
    rows = repo.list_evidence(db, investigation_id)
    return [EvidenceOut(evidence_id=r.evidence_id, investigation_id=r.investigation_id, source_tool=r.source_tool, evidence_type=r.evidence_type, payload=r.payload, timestamp=r.timestamp) for r in rows]


@app.get("/reports/{report_id}", response_model=ReportOut)
def get_report(report_id: str, db: Session = Depends(get_db)):
    from fastapi import HTTPException

    r = repo.get_report(db, report_id)
    if not r:
        # allow lookup by investigation id as convenience
        r = repo.get_report_by_investigation(db, report_id)
    if not r:
        raise HTTPException(404, "report not found")
    return ReportOut(report_id=r.report_id, investigation_id=r.investigation_id, report_json=r.report_json, generated_at=r.generated_at, reviewer_status=r.reviewer_status)
