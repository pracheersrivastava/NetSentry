"""Normalizer: packet summaries -> FlowIn dicts. Minimal for MVP (passthrough + defaults)."""
from datetime import datetime, timezone


def normalize(raw: dict, i: int = 0) -> dict:
    ts = raw.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except ValueError:
            ts = datetime.now(timezone.utc)
    if ts is None:
        ts = datetime.now(timezone.utc)
    return {
        "flow_id": raw.get("flow_id") or f"FLOW-{i:04d}",
        "timestamp": ts,
        "src_ip": raw.get("src_ip", "192.168.1.10"),
        "dst_ip": raw.get("dst_ip", "10.0.0.25"),
        "src_port": int(raw.get("src_port", 50000 + i)),
        "dst_port": int(raw.get("dst_port", 443)),
        "protocol": raw.get("protocol", "TCP"),
        "duration": float(raw.get("duration", 1.0)),
        "orig_bytes": int(raw.get("orig_bytes", 1000)),
        "resp_bytes": int(raw.get("resp_bytes", 1000)),
        "orig_pkts": int(raw.get("orig_pkts", 10)),
        "resp_pkts": int(raw.get("resp_pkts", 10)),
    }
