"""Thin CRUD helpers. Routers call these, never raw SQL."""
from sqlalchemy.orm import Session
from . import models


def upsert_flow(s: Session, flow: dict) -> models.NetworkFlow:
    obj = s.get(models.NetworkFlow, flow["flow_id"])
    if obj is None:
        obj = models.NetworkFlow(**flow)
        s.add(obj)
    else:
        for k, v in flow.items():
            setattr(obj, k, v)
    s.commit()
    s.refresh(obj)
    return obj


def list_flows(s: Session, limit: int = 50, offset: int = 0, src_ip: str | None = None):
    q = s.query(models.NetworkFlow).order_by(models.NetworkFlow.timestamp.desc())
    if src_ip:
        q = q.filter(models.NetworkFlow.src_ip == src_ip)
    return q.offset(offset).limit(limit).all()


def create_event(s: Session, event: dict) -> models.AnomalyEvent:
    obj = models.AnomalyEvent(**event)
    s.add(obj)
    s.commit()
    s.refresh(obj)
    return obj


def list_events(s: Session, limit: int = 50, status: str | None = None, min_score: float | None = None):
    q = s.query(models.AnomalyEvent).order_by(models.AnomalyEvent.created_at.desc())
    if status:
        q = q.filter(models.AnomalyEvent.status == status)
    if min_score is not None:
        q = q.filter(models.AnomalyEvent.anomaly_score >= min_score)
    return q.limit(limit).all()


def get_event(s: Session, event_id: str):
    return s.get(models.AnomalyEvent, event_id)


def get_flow(s: Session, flow_id: str):
    return s.get(models.NetworkFlow, flow_id)


def create_investigation(s: Session, inv: dict) -> models.Investigation:
    obj = models.Investigation(**inv)
    s.add(obj)
    s.commit()
    s.refresh(obj)
    return obj


def get_investigation(s: Session, investigation_id: str):
    return s.get(models.Investigation, investigation_id)


def finish_investigation(s: Session, investigation_id: str, outcome: str) -> models.Investigation | None:
    from datetime import datetime, timezone

    obj = s.get(models.Investigation, investigation_id)
    if obj is None:
        return None
    obj.state = "done"
    obj.completed_at = datetime.now(timezone.utc)
    obj.outcome = outcome
    s.commit()
    s.refresh(obj)
    return obj


def add_evidence(s: Session, ev: dict) -> models.Evidence:
    obj = models.Evidence(**ev)
    s.add(obj)
    s.commit()
    s.refresh(obj)
    return obj


def list_evidence(s: Session, investigation_id: str):
    return s.query(models.Evidence).filter(models.Evidence.investigation_id == investigation_id).order_by(models.Evidence.timestamp).all()


def add_tool_call(s: Session, call: dict) -> models.ToolCall:
    obj = models.ToolCall(**call)
    s.add(obj)
    s.commit()
    s.refresh(obj)
    return obj


def save_report(s: Session, rep: dict) -> models.Report:
    obj = models.Report(**rep)
    s.add(obj)
    s.commit()
    s.refresh(obj)
    return obj


def get_report(s: Session, report_id: str):
    return s.get(models.Report, report_id)


def get_report_by_investigation(s: Session, investigation_id: str):
    return s.query(models.Report).filter(models.Report.investigation_id == investigation_id).first()


def find_event_for_flow(s: Session, flow_id: str):
    """Dedupe: re-ingesting same flow_id reuses existing event instead of new ANM."""
    return s.query(models.AnomalyEvent).filter(models.AnomalyEvent.flow_id == flow_id).order_by(models.AnomalyEvent.created_at.desc()).first()


def update_event_score(s: Session, event_id: str, score: float, model_version: str):
    obj = s.get(models.AnomalyEvent, event_id)
    if obj is None:
        return None
    obj.anomaly_score = score
    obj.model_version = model_version
    s.commit()
    s.refresh(obj)
    return obj


def set_event_status(s: Session, event_id: str, status: str):
    obj = s.get(models.AnomalyEvent, event_id)
    if obj is None:
        return None
    obj.status = status
    s.commit()
    s.refresh(obj)
    return obj


def list_investigations(s: Session, limit: int = 50):
    return s.query(models.Investigation).order_by(models.Investigation.started_at.desc()).limit(limit).all()


def get_investigation_by_event(s: Session, event_id: str):
    return s.query(models.Investigation).filter(models.Investigation.event_id == event_id).order_by(models.Investigation.started_at.desc()).first()


def set_report_review(s: Session, report_id: str, status: str):
    obj = s.get(models.Report, report_id)
    if obj is None:
        return None
    obj.reviewer_status = status
    s.commit()
    s.refresh(obj)
    return obj


def upsert_model_version(s: Session, model_id: str, version: str, artifact_path: str = "", metrics: dict | None = None):
    obj = s.get(models.ModelVersion, model_id)
    if obj is None:
        obj = models.ModelVersion(model_id=model_id, version=version, training_data="", metrics=metrics or {}, artifact_path=artifact_path)
        s.add(obj)
    else:
        obj.version = version
        obj.artifact_path = artifact_path
        if metrics is not None:
            obj.metrics = metrics
    s.commit()
    s.refresh(obj)
    return obj


def bulk_upsert_flows_events(s: Session, raws: list[dict], events: list[dict | None]) -> None:
    """Scale path: ONE commit for N flows + M events (live/batch). Single ingest keeps per-row commit."""
    for raw in raws:
        obj = s.get(models.NetworkFlow, raw["flow_id"])
        if obj is None:
            s.add(models.NetworkFlow(**raw))
        else:
            for k, v in raw.items():
                setattr(obj, k, v)
    for ev in events:
        if ev is None:
            continue
        if s.get(models.AnomalyEvent, ev["event_id"]) is None:
            s.add(models.AnomalyEvent(**ev))
    s.commit()
