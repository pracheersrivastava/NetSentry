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
from agent.graph import run_graph_investigation
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
    # log active model version so stub->real swap is auditable (never breaks if DB down)
    try:
        s = SessionLocal()
        repo.upsert_model_version(s, _detector.model_name, _detector.model_version, os.getenv("MODEL_PATH", ""), {"source": "startup"})
        s.close()
    except Exception as e:
        print(f"[api] model version log skipped: {e}")
    yield


app = FastAPI(title="NetSentry AI backend", version="0.1.0", lifespan=lifespan)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


def _score_and_store(flow: FlowIn, db: Session):
    """Shared ingest core: normalize -> featurize -> predict -> upsert flow -> dedupe event."""
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
    # dedupe: same flow_id reuses existing event (replay-safe, live-safe)
    existing = repo.find_event_for_flow(db, raw["flow_id"])
    if existing:
        repo.update_event_score(db, existing.event_id, res.anomaly_score, res.model_version)
        return raw["flow_id"], res, existing.event_id if existing.status != "store_only" else None
    event = build_event(raw["flow_id"], res.anomaly_score, res.model_version, _thresholds)
    event_id = None
    if event:
        repo.create_event(db, event)
        event_id = event["event_id"]
    return raw["flow_id"], res, event_id


@app.post("/flows/ingest", response_model=IngestOut)
def ingest_flow(flow: FlowIn, db: Session = Depends(get_db)):
    flow_id, res, event_id = _score_and_store(flow, db)
    return IngestOut(flow_id=flow_id, anomaly_score=res.anomaly_score, prediction=res.prediction, event_id=event_id)


@app.post("/flows/batch", response_model=list[IngestOut])
def ingest_batch(flows: list[FlowIn], db: Session = Depends(get_db)):
    """Live-capture path: 1 HTTP call for N flows, ONE commit (scale-safe). Same scoring as single ingest."""
    from events.event_manager import build_event as _build

    det = _get_detector()
    raws, events, out_meta = [], [], []
    for i, f in enumerate(flows[:500]):  # cap protects demo + prod from 10k-row bombs
        raw = normalize(f.model_dump(exclude_none=False), i)
        if not raw["flow_id"]:
            raw["flow_id"] = f"FLOW-{uuid.uuid4().hex[:8].upper()}"
        if not raw.get("timestamp"):
            raw["timestamp"] = datetime.now(timezone.utc)
        feats = extract_features(raw, {})
        res = det.predict(feats)
        raw["features"] = feats
        raws.append(raw)
        # keep current dedupe semantic: reuse existing event id when present
        existing = repo.find_event_for_flow(db, raw["flow_id"])
        if existing:
            repo.update_event_score(db, existing.event_id, res.anomaly_score, res.model_version)
            out_meta.append((raw["flow_id"], res, existing.event_id))
        else:
            ev = _build(raw["flow_id"], res.anomaly_score, res.model_version, _thresholds)
            events.append(ev)
            out_meta.append((raw["flow_id"], res, ev["event_id"] if ev else None))
    # single transaction for all new rows
    repo.bulk_upsert_flows_events(db, raws, events)
    return [IngestOut(flow_id=fid, anomaly_score=r.anomaly_score, prediction=r.prediction, event_id=eid) for fid, r, eid in out_meta]


@app.get("/flows")
def get_flows(limit: int = 50, offset: int = 0, src_ip: str | None = None, db: Session = Depends(get_db)):
    rows = repo.list_flows(db, limit=limit, offset=offset, src_ip=src_ip)
    return [
        {"flow_id": r.flow_id, "src_ip": r.src_ip, "dst_ip": r.dst_ip, "dst_port": r.dst_port, "protocol": r.protocol, "features": r.features}
        for r in rows
    ]


@app.get("/flows/{flow_id}")
def get_flow(flow_id: str, db: Session = Depends(get_db)):
    from fastapi import HTTPException

    r = repo.get_flow(db, flow_id)
    if not r:
        raise HTTPException(404, "flow not found")
    return {"flow_id": r.flow_id, "src_ip": r.src_ip, "dst_ip": r.dst_ip, "src_port": r.src_port, "dst_port": r.dst_port, "protocol": r.protocol, "features": r.features}


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


@app.patch("/anomalies/{event_id}", response_model=AnomalyOut)
def patch_anomaly(event_id: str, status: str, db: Session = Depends(get_db)):
    """Analyst triage: open -> closed/monitoring. Dashboard needs this day 1."""
    from fastapi import HTTPException

    if status not in ("open", "monitoring", "investigating", "closed"):
        raise HTTPException(400, "bad status")
    r = repo.set_event_status(db, event_id, status)
    if not r:
        raise HTTPException(404, "event not found")
    return AnomalyOut(event_id=r.event_id, flow_id=r.flow_id, anomaly_score=r.anomaly_score, model_version=r.model_version, status=r.status, created_at=r.created_at)


@app.post("/model/predict", response_model=PredictOut)
def model_predict(flow: FlowIn):
    det = _get_detector()
    raw = normalize(flow.model_dump(), 0)
    feats = extract_features(raw, {})
    res = det.predict(feats)
    return PredictOut(flow_id=raw.get("flow_id") or "FLOW-TEST", model=res.model, model_version=res.model_version, anomaly_score=res.anomaly_score, prediction=res.prediction, features_used=res.features_used)


@app.get("/model/info")
def model_info():
    """Dashboard + ML team: what model is live, what features it expects. Swap-safe contract."""
    import json

    det = _get_detector()
    with open("features/schema.json") as f:
        schema = json.load(f)
    return {"model": det.model_name, "model_version": det.model_version, "feature_order": schema["feature_order"], "artifact": os.getenv("MODEL_PATH", "")}


@app.post("/model/validate")
def model_validate():
    """ML team: drop .joblib then POST here to check compatibility WITHOUT restarting."""
    from ml.validate import validate_artifact

    ok, report = validate_artifact(os.getenv("MODEL_PATH", "ml/models/isolation_forest_v1.joblib"))
    return {"ok": ok, **report}


@app.post("/investigations/{event_id}", response_model=InvestigationOut)
def start_investigation(event_id: str, db: Session = Depends(get_db)):
    """LangGraph investigation (dynamic selector, deterministic risk). LLM only enhances report."""
    from fastapi import HTTPException

    if not repo.get_event(db, event_id):
        raise HTTPException(404, "event not found")
    # idempotent: re-POST same event reuses investigation (no LLM re-burn, no duplicate INVs)
    existing = repo.get_investigation_by_event(db, event_id)
    if existing:
        return InvestigationOut(investigation_id=existing.investigation_id, event_id=existing.event_id, state=existing.state, started_at=existing.started_at, completed_at=existing.completed_at, outcome=existing.outcome)
    inv_id = run_graph_investigation(db, event_id)
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
        from llm.synthesizer import synthesize, model_name

        llm_out = synthesize(
            {"event_id": ev.event_id, "anomaly_score": ev.anomaly_score},
            [{"source_tool": e.source_tool, "payload": e.payload} for e in ev_rows],
        )
        if llm_out:
            rep_json["findings"] = llm_out.get("findings") or rep_json["findings"]
            if llm_out.get("mitre_techniques"):
                rep_json["mitre_techniques"] = llm_out.get("mitre_techniques")
            rep_json["confidence"] = llm_out.get("confidence", rep_json["confidence"])
            rep_json["uncertainties"] = llm_out.get("uncertainties", rep_json["uncertainties"])
            rep_json["llm_model"] = model_name()
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


@app.get("/investigations", response_model=list[InvestigationOut])
def list_investigations(limit: int = 50, db: Session = Depends(get_db)):
    rows = repo.list_investigations(db, limit=limit)
    return [InvestigationOut(investigation_id=r.investigation_id, event_id=r.event_id, state=r.state, started_at=r.started_at, completed_at=r.completed_at, outcome=r.outcome) for r in rows]


@app.post("/reports/{report_id}/review", response_model=ReportOut)
def review_report(report_id: str, status: str, db: Session = Depends(get_db)):
    """Analyst disposition: pending -> approved/rejected."""
    from fastapi import HTTPException

    if status not in ("pending", "approved", "rejected"):
        raise HTTPException(400, "bad status")
    r = repo.set_report_review(db, report_id, status)
    if not r:
        raise HTTPException(404, "report not found")
    return ReportOut(report_id=r.report_id, investigation_id=r.investigation_id, report_json=r.report_json, generated_at=r.generated_at, reviewer_status=r.reviewer_status)
