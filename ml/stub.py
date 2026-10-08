"""Deterministic heuristic stub — demo placeholder with same interface as real model.

Scores high on: large bytes/sec, many pkts/sec, port-sweep signals, failed-ratio.
Never import sklearn here so demo runs without ML deps.
"""
from .interface import BaseDetector, PredictionResult


class StubDetector(BaseDetector):
    model_name = "isolation_forest"
    model_version = "v0-stub"

    def predict(self, features: dict) -> PredictionResult:
        bps = float(features.get("bytes_per_sec", 0))
        pps = float(features.get("pkts_per_sec", 0))
        uniq_ports = float(features.get("unique_dst_ports_5min", 1))
        fail = float(features.get("failed_conn_ratio_5min", 0))

        score = 0.1
        if bps > 20000:
            score += 0.35
        if bps > 50000:
            score += 0.25
        if pps > 20:
            score += 0.15
        if uniq_ports >= 10:
            score += 0.25
        if fail > 0.3:
            score += 0.2
        score = max(0.0, min(0.99, score))

        if score >= 0.85:
            pred = "anomaly"
        elif score >= 0.6:
            pred = "monitor"
        else:
            pred = "normal"
        return PredictionResult(
            anomaly_score=round(score, 3),
            prediction=pred,
            model=self.model_name,
            model_version=self.model_version,
            features_used=features,
        )
