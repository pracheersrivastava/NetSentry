"""Event manager: ML score -> anomaly_events row (dedupe-lite for MVP)."""
import uuid
from .threshold import classify


def build_event(flow_id: str, score: float, model_version: str, thresholds: dict) -> dict | None:
    status = classify(score, thresholds)
    if status == "store_only":
        return None
    return {
        "event_id": f"ANM-{uuid.uuid4().hex[:8].upper()}",
        "flow_id": flow_id,
        "anomaly_score": score,
        "model_version": model_version,
        "status": status,
    }
