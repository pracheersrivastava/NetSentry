"""SQLAlchemy ORM models — FROZEN CONTRACT (Report Table 8).
Do not rename tables/columns without migration + API schema update.
SQLite for MVP, Postgres-ready via DATABASE_URL.
"""
from sqlalchemy import String, Float, Integer, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class NetworkFlow(Base):
    __tablename__ = "network_flows"
    flow_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    src_ip: Mapped[str] = mapped_column(String, index=True)
    dst_ip: Mapped[str] = mapped_column(String, index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String)
    duration: Mapped[float] = mapped_column(Float)
    orig_bytes: Mapped[int] = mapped_column(Integer)
    resp_bytes: Mapped[int] = mapped_column(Integer)
    orig_pkts: Mapped[int] = mapped_column(Integer)
    resp_pkts: Mapped[int] = mapped_column(Integer)
    features: Mapped[dict] = mapped_column(JSON, default=dict)


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"
    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    flow_id: Mapped[str] = mapped_column(String, ForeignKey("network_flows.flow_id"), index=True)
    anomaly_score: Mapped[float] = mapped_column(Float, index=True)
    model_version: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="open", index=True)  # open|monitoring|investigating|closed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Investigation(Base):
    __tablename__ = "investigations"
    investigation_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(String, ForeignKey("anomaly_events.event_id"), index=True)
    state: Mapped[str] = mapped_column(String, default="queued", index=True)  # queued|running|done|failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome: Mapped[str | None] = mapped_column(Text, nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"
    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.investigation_id"), index=True)
    source_tool: Mapped[str] = mapped_column(String, index=True)
    evidence_type: Mapped[str] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ToolCall(Base):
    __tablename__ = "tool_calls"
    call_id: Mapped[str] = mapped_column(String, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.investigation_id"), index=True)
    tool_name: Mapped[str] = mapped_column(String)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    execution_time: Mapped[float] = mapped_column(Float, default=0.0)


class Report(Base):
    __tablename__ = "reports"
    report_id: Mapped[str] = mapped_column(String, primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.investigation_id"), index=True)
    report_json: Mapped[dict] = mapped_column(JSON, default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    reviewer_status: Mapped[str] = mapped_column(String, default="pending", index=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"
    model_id: Mapped[str] = mapped_column(String, primary_key=True)
    version: Mapped[str] = mapped_column(String)
    training_data: Mapped[str] = mapped_column(String, default="")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_path: Mapped[str] = mapped_column(String, default="")
