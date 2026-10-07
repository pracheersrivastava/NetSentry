"""Real sklearn wrapper — used only when ML team drops a .joblib. Not needed for stub demo."""
import joblib
from .interface import BaseDetector, PredictionResult


class SklearnDetector(BaseDetector):
    model_name = "isolation_forest"
    model_version = "v1.0"

    def __init__(self, path: str):
        from .validate import validate_artifact

        ok, report = validate_artifact(path)
        if not ok:
            raise ValueError(f"artifact failed validation: {report}")
        self.model_version = report.get("version", "v1.0")
        blob = joblib.load(path)
        if isinstance(blob, dict) and "model" in blob:
            self.model = blob["model"]
            self.scaler = blob.get("scaler")
            self.feature_order = blob.get("feature_order")
        else:
            self.model = blob
            self.scaler = None
            self.feature_order = None

    def predict(self, features: dict) -> PredictionResult:
        import json

        try:
            order = self.feature_order
            if order is None:
                with open("features/schema.json") as f:
                    order = json.load(f)["feature_order"]
            vec = [[float(features.get(k, 0) or 0) for k in order]]
            if self.scaler is not None:
                vec = self.scaler.transform(vec)
            # IsolationForest: lower decision_function = more anomalous; normalize to 0-1
            if hasattr(self.model, "decision_function"):
                raw = self.model.decision_function(vec)[0]
                score = float(max(0.0, min(1.0, 0.5 - raw)))
            else:  # fallback for classifiers emitting -1/1
                pred = self.model.predict(vec)[0]
                score = 0.9 if int(pred) == -1 else 0.1
            score = round(max(0.0, min(0.99, score)), 3)
        except Exception:
            # never-break: degraded score instead of 500 when ML misbehaves
            score = 0.5
            features = {**features, "_degraded": True}
        pred = "anomaly" if score >= 0.85 else ("monitor" if score >= 0.6 else "normal")
        return PredictionResult(score, pred, self.model_name, self.model_version, features)
