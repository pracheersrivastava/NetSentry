"""Dynamic tool selector — rules today, LLM override tomorrow. Same signature either way.

Round 0 (always): event lookup + traffic analysis + history (MVP 3-tool set).
Round 1 (only if validation fails): re-run the single most informative missing tool.
Max 2 rounds, max 6 calls total (quota-safe).
"""
from agent.state import InvestigationState


def select_next_tools(state: InvestigationState) -> list[tuple[str, dict]]:
    event_id = state["event_id"]
    have = {e["source_tool"] for e in state.get("evidence", [])}
    rounds = state.get("rounds", 0)
    src_ip = (state.get("event", {}).get("flow") or {}).get("src_ip", "unknown")

    if rounds == 0:
        plan = []
        if "get_network_event" not in have:
            plan.append(("get_network_event", {"event_id": event_id}))
        if "analyze_connections" not in have:
            plan.append(("analyze_connections", {"src_ip": src_ip}))
        if "search_historical_traffic" not in have:
            plan.append(("search_historical_traffic", {"src_ip": src_ip}))
        return plan
    # round 1: fill the single biggest gap
    if "analyze_connections" not in have:
        return [("analyze_connections", {"src_ip": src_ip})]
    if "search_historical_traffic" not in have:
        return [("search_historical_traffic", {"src_ip": src_ip})]
    return []
