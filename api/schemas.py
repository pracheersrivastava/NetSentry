"""Pydantic schemas — FROZEN API CONTRACT. Dashboard depends on these."""
from pydantic import BaseModel, Field
from datetime import datetime


class FlowIn(BaseModel):
    flow_id: str = Field(default_factory=lambda: "")
    timestamp: datetime | None = None
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str = "TCP"
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0


class PredictOut(BaseModel):
    flow_id: str
    model: str
    model_version: str
    anomaly_score: float
    prediction: str  # anomaly|monitor|normal
    features_used: dict


class AnomalyOut(BaseModel):
    event_id: str
    flow_id: str
    anomaly_score: float
    model_version: str
    status: str
    created_at: datetime


class IngestOut(BaseModel):
    flow_id: str
    anomaly_score: float
    prediction: str
    event_id: str | None = None


class IngestIn(BaseModel):
    """Wrapper so script replay can send behavioral context alongside flow.
    Live aggregator later fills ctx server-side; field stays for compat."""

    flow: FlowIn
    ctx: dict | None = None


class PredictIn(BaseModel):
    flow: FlowIn
    ctx: dict | None = None
