"""Model interface — THE seam that makes stub swappable with real IsolationForest."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class PredictionResult:
    anomaly_score: float  # 0.0-1.0 normalized
    prediction: str  # anomaly|monitor|normal
    model: str
    model_version: str
    features_used: dict


class BaseDetector(ABC):
    model_name: str = "base"
    model_version: str = "v0"

    @abstractmethod
    def predict(self, features: dict) -> PredictionResult:
        raise NotImplementedError
