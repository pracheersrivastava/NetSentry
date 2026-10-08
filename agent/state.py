"""InvestigationState — LangGraph state schema. Mirrors DB rows for resume-safety."""
from typing import TypedDict


class InvestigationState(TypedDict, total=False):
    event_id: str
    event: dict  # Full anomaly event + flow record (all 12 features & telemetry)
    evidence: list[dict]  # [{source_tool, payload}]
    tool_results: list[dict]  # raw + execution_time
    feature_attributions: list[dict]  # [{feature, value, threshold, signal, severity}]
    hypotheses: list[dict]  # [{hypothesis, status, trigger_feature, confidence, corroborating_tools, evidence_summary}]
    risk_factors: dict  # {factor: contribution}
    risk_assessment: dict  # Full explainable risk object (composite, level, rationale, breakdown)
    findings: list[str]
    risk_level: str  # low|medium|high|critical
    confidence: float
    report: dict
    investigation_log: list[str]  # node trace
    rounds: int  # evidence loops used (max 2)


def fresh_state(event_id: str) -> InvestigationState:
    return {
        "event_id": event_id,
        "event": {},
        "evidence": [],
        "tool_results": [],
        "feature_attributions": [],
        "hypotheses": [],
        "risk_factors": {},
        "risk_assessment": {},
        "findings": [],
        "risk_level": "low",
        "confidence": 0.0,
        "report": {},
        "investigation_log": [],
        "rounds": 0,
    }
