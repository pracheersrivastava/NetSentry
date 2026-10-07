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
