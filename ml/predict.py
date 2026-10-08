"""Factory: returns real sklearn model if MODEL_PATH exists, else StubDetector.

Real-model contract for ML team:
- artifact must be joblib dict {model, scaler, feature_order} OR bare sklearn model
- feature_order must match features/schema.json
- wrapper normalizes IsolationForest decision_function to 0-1
"""
import os

from .interface import BaseDetector
from .stub import StubDetector


def get_detector() -> BaseDetector:
    model_path = os.getenv("MODEL_PATH", "ml/models/isolation_forest_v1.joblib")
    if model_path and os.path.exists(model_path):
        try:
            from .real import SklearnDetector  # lazy import, needs sklearn

            det = SklearnDetector(model_path)
            print(f"[ml] loaded real model {model_path} version={det.model_version}")
            return det
        except Exception as e:
            print(f"[ml] WARN: failed to load {model_path}: {e}, falling back to stub")
    stub = StubDetector()
    print(f"[ml] using stub {stub.model_version} (no artifact at {model_path})")
    return stub
