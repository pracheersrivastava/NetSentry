"""InvestigationState — LangGraph state schema. Mirrors DB rows for resume-safety."""
from typing import TypedDict


class InvestigationState(TypedDict, total=False):
    event_id: str
    event: dict
    evidence: list[dict]  # [{source_tool, payload}]
    tool_results: list[dict]  # raw + execution_time
    findings: list[str]
    risk_level: str  # low|medium|high|critical
    confidence: float
    report: dict
    investigation_log: list[str]  # node trace
    rounds: int  # evidence loops used (max 2)


def fresh_state(event_id: str) -> InvestigationState:
    return {"event_id": event_id, "event": {}, "evidence": [], "tool_results": [], "findings": [], "risk_level": "low", "confidence": 0.0, "report": {}, "investigation_log": [], "rounds": 0}
