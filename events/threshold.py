"""Threshold policy loader — thresholds live in configs/threshold.yaml, never hardcoded."""
import os
import yaml


def load_thresholds(path: str | None = None) -> dict:
    path = path or os.getenv("THRESHOLD_CONFIG", "configs/threshold.yaml")
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        return {"investigate_at": float(cfg.get("investigate_at", 0.85)), "monitor_at": float(cfg.get("monitor_at", 0.60))}
    except FileNotFoundError:
        return {"investigate_at": 0.85, "monitor_at": 0.60}


def classify(score: float, thresholds: dict) -> str:
    if score >= thresholds["investigate_at"]:
        return "open"
    if score >= thresholds["monitor_at"]:
        return "monitoring"
    return "store_only"
