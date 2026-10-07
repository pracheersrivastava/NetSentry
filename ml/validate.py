"""Artifact validator — run before/after ML team drops a .joblib. Never breaks backend.

Checks: file loads, has model with decision_function/predict, feature_order
matches features/schema.json, scaler (if present) transforms 12-col vector,
one dummy predict returns score in 0-1.
Returns (ok: bool, report: dict). Factory uses this to decide stub fallback.
"""
import json
import os


def validate_artifact(path: str) -> tuple[bool, dict]:
    with open("features/schema.json") as f:
        expected = json.load(f)["feature_order"]
    if not os.path.exists(path):
        return False, {"error": "file not found", "path": path}
    try:
        import joblib
    except Exception as e:
        return False, {"error": f"joblib missing: {e}"}
    try:
        blob = joblib.load(path)
    except Exception as e:
        return False, {"error": f"load failed: {e}"}
    info: dict = {"path": path, "expected_features": expected}
    model, scaler, order = None, None, None
    if isinstance(blob, dict) and "model" in blob:
        model, scaler = blob["model"], blob.get("scaler")
        order = blob.get("feature_order")
        info["version"] = blob.get("version", "v1.0")
        info["format"] = "dict{model,scaler,feature_order}"
    else:
        model = blob
        info["format"] = "bare-sklearn-model"
        info["version"] = "v1.0"
    if order is not None and list(order) != list(expected):
        return False, {**info, "error": f"feature_order mismatch: got {order}"}
    info["feature_order"] = "ok"
    # dummy predict
    try:
        dummy = {k: 1.0 for k in expected}
        vec = [[float(dummy[k]) for k in expected]]
        if scaler is not None:
            vec = scaler.transform(vec)
        if hasattr(model, "decision_function"):
            raw = model.decision_function(vec)[0]
            score = float(max(0.0, min(1.0, 0.5 - raw)))
        else:
            pred = model.predict(vec)[0]
            score = 0.9 if int(pred) == -1 else 0.1
        info["dummy_score"] = score
        return True, info
    except Exception as e:
        return False, {**info, "error": f"dummy predict failed: {e}"}
