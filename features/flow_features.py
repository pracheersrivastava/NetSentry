"""Feature engineering — single place where FlowIn -> model vector happens."""
import json
import os

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.json")
with open(_SCHEMA_PATH) as f:
    FEATURE_ORDER = json.load(f)["feature_order"]


def extract_features(flow: dict, ctx: dict | None = None) -> dict:
    """flow: raw FlowIn dict. ctx: rolling-window hints (from script/demo for now, live aggregator later)."""
    ctx = ctx or {}
    duration = max(float(flow.get("duration", 0) or 0), 0.001)
    orig_bytes = int(flow.get("orig_bytes", 0))
    resp_bytes = int(flow.get("resp_bytes", 0))
    orig_pkts = int(flow.get("orig_pkts", 0))
    resp_pkts = int(flow.get("resp_pkts", 0))
    feats = {
        "duration": float(flow.get("duration", 0)),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "total_bytes": orig_bytes + resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "bytes_per_sec": (orig_bytes + resp_bytes) / duration,
        "pkts_per_sec": (orig_pkts + resp_pkts) / duration,
        "dst_port": int(flow.get("dst_port", 0)),
        "protocol_TCP": 1 if str(flow.get("protocol", "TCP")).upper() == "TCP" else 0,
        "unique_dst_ports_5min": int(ctx.get("unique_dst_ports_5min", 1)),
        "failed_conn_ratio_5min": float(ctx.get("failed_conn_ratio_5min", 0.0)),
    }
    return {k: feats[k] for k in FEATURE_ORDER}
