"""FastAPI backend — Option A (in-process model). Single container demo."""
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session

from database.db import init_db, SessionLocal
from database import repository as repo
from api.schemas import FlowIn, PredictOut, AnomalyOut, IngestOut
from features.flow_features import extract_features
from ml.predict import get_detector
from events.threshold import load_thresholds
from events.event_manager import build_event
from capture.normalizer import normalize

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
    print(f"[api] detector={_detector.model_name}:{_detector.model_version} thresholds={_thresholds}")
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
    d = _get_detector()
    return {"status": "ok", "model": getattr(d, "model_version", "unloaded")}


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


@app.post("/investigations/{event_id}")
def start_investigation(event_id: str):
    # Agent team plugs LangGraph here (Phase 2). Stub keeps API stable.
    return {"investigation_id": f"INV-{uuid.uuid4().hex[:8].upper()}", "event_id": event_id, "state": "queued", "note": "agent not wired yet (stub)"}
