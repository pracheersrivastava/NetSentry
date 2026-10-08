"""Deterministic risk assessment — math, not LLM. LLM explains it later."""
from agent.state import InvestigationState


def assess(state: InvestigationState) -> InvestigationState:
    ev = state.get("event", {})
    score = float(ev.get("anomaly_score", 0))
    by_tool = {e["source_tool"]: e["payload"] for e in state.get("evidence", [])}
    traffic = by_tool.get("analyze_connections", {})
    history = by_tool.get("search_historical_traffic", {})

    scan_like = bool(traffic.get("scan_like"))
    novel = history.get("past_flow_count", 99) <= 2
    volume = float((traffic.get("total_bytes") or 0)) > 200000

    risk = 0.5 * score
    if scan_like:
        risk += 0.2
    if novel and score >= 0.6:
        risk += 0.15
    if volume:
        risk += 0.15
    risk = max(0.0, min(1.0, risk))
    level = "low" if risk < 0.4 else ("medium" if risk < 0.65 else ("high" if risk < 0.85 else "critical"))
    state["risk_level"] = level
    state["confidence"] = round(0.4 + 0.25 * min(len(state.get("evidence", [])), 3) / 3 + (0.15 if level in ("high", "critical") else 0.0), 2)
    state["investigation_log"] = [*state.get("investigation_log", []), f"risk:{level}({risk:.2f}) scan={scan_like} novel={novel}"]
    return state
