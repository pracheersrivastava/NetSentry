"""Dynamic tool selector — rules today, LLM override tomorrow. Same signature either way.

Round 0:
- Core 3-tool baseline (event lookup + traffic analysis + history)
- Contextual enrichment (destination analysis + similar incidents + DNS + reputation)
Round 1 (gap fill): re-run any missing tools if validation requires.
"""
from agent.state import InvestigationState


def select_next_tools(state: InvestigationState) -> list[tuple[str, dict]]:
    event_id = state["event_id"]
    have = {e["source_tool"] for e in state.get("evidence", [])}
    rounds = state.get("rounds", 0)
    flow = (state.get("event", {}).get("flow") or {})
    src_ip = flow.get("src_ip", "unknown")
    dst_ip = flow.get("dst_ip", "unknown")
    dst_port = flow.get("dst_port")

    if rounds == 0:
        plan = []
        # Core 3-tool baseline
        if "get_network_event" not in have:
            plan.append(("get_network_event", {"event_id": event_id}))
        if "analyze_connections" not in have and src_ip != "unknown":
            plan.append(("analyze_connections", {"src_ip": src_ip}))
        if "search_historical_traffic" not in have and src_ip != "unknown":
            plan.append(("search_historical_traffic", {"src_ip": src_ip}))

        # Contextual tools (full suite)
        if state.get("scope") != "mvp":
            if "analyze_destination" not in have and dst_ip and dst_ip != "unknown":
                plan.append(("analyze_destination", {"dst_ip": dst_ip, "dst_port": dst_port}))
            if "search_similar_incidents" not in have and src_ip != "unknown":
                plan.append(("search_similar_incidents", {"src_ip": src_ip}))
            if "lookup_dns" not in have:
                target = dst_ip if (dst_ip and dst_ip != "unknown") else src_ip
                if target != "unknown":
                    plan.append(("lookup_dns", {"domain_or_ip": target}))
            if "lookup_reputation" not in have and src_ip != "unknown":
                plan.append(("lookup_reputation", {"indicator": src_ip}))

        return plan

    # Round 1: fill any missing critical tools
    missing = []
    if "analyze_connections" not in have and src_ip != "unknown":
        missing.append(("analyze_connections", {"src_ip": src_ip}))
    if "search_historical_traffic" not in have and src_ip != "unknown":
        missing.append(("search_historical_traffic", {"src_ip": src_ip}))
    if "analyze_destination" not in have and dst_ip and dst_ip != "unknown":
        missing.append(("analyze_destination", {"dst_ip": dst_ip, "dst_port": dst_port}))
    return missing[:2]
