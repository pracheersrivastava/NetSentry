"""LangGraph investigation runner. Same DB rows + same API as stub; dynamic selector inside.

Nodes: receive -> initial_analysis -> select -> tools -> validate
                       ^------------------------| (max 2 rounds)
                     -> risk -> END
Report building stays in api/main.py (unchanged).
Falls back to manual node loop if langgraph is missing, so tests never break.
"""
import uuid
from sqlalchemy.orm import Session
from database import repository as repo
from agent.state import InvestigationState, fresh_state
from agent.selector import select_next_tools
from agent.risk import assess
from agent.tools.deterministic import run_tool


def compute_feature_attributions(features: dict, score: float) -> list[dict]:
    """Identify which features deviated from baseline and contributed to the anomaly."""
    attributions = []
    bps = float(features.get("bytes_per_sec", 0))
    pps = float(features.get("pkts_per_sec", 0))
    uniq_ports = int(features.get("unique_dst_ports_5min", 1))
    fail_ratio = float(features.get("failed_conn_ratio_5min", 0))
    total_bytes = int(features.get("total_bytes", 0))
    duration = float(features.get("duration", 0))

    if bps > 20000:
        attributions.append({
            "feature": "bytes_per_sec",
            "value": round(bps, 1),
            "threshold": 20000.0,
            "signal": "High bandwidth throughput anomaly",
            "severity": "critical" if bps > 100000 else "high",
        })
    if pps > 20:
        attributions.append({
            "feature": "pkts_per_sec",
            "value": round(pps, 1),
            "threshold": 20.0,
            "signal": "High packet rate burst",
            "severity": "high" if pps > 100 else "medium",
        })
    if uniq_ports >= 10:
        attributions.append({
            "feature": "unique_dst_ports_5min",
            "value": uniq_ports,
            "threshold": 10,
            "signal": "Horizontal port diversity sweep",
            "severity": "critical" if uniq_ports >= 25 else "high",
        })
    if fail_ratio > 0.3:
        attributions.append({
            "feature": "failed_conn_ratio_5min",
            "value": round(fail_ratio, 2),
            "threshold": 0.3,
            "signal": "Elevated connection failure ratio",
            "severity": "medium",
        })
    if duration < 0.5 and total_bytes > 50000:
        attributions.append({
            "feature": "duration_vs_bytes",
            "value": f"{total_bytes} bytes in {duration}s",
            "threshold": "50KB in <0.5s",
            "signal": "Abrupt volumetric traffic spike",
            "severity": "high",
        })
    return attributions


def formulate_hypotheses(attributions: list[dict], score: float) -> list[dict]:
    """Formulate testable investigation hypotheses from feature signals."""
    hypotheses = []
    attr_names = {a["feature"] for a in attributions}

    if "unique_dst_ports_5min" in attr_names:
        hypotheses.append({
            "hypothesis": "network_reconnaissance_port_scan",
            "status": "suspected",
            "trigger_feature": "unique_dst_ports_5min",
            "confidence": 0.85,
            "corroborating_tools": ["analyze_connections", "analyze_destination"],
        })
    if "bytes_per_sec" in attr_names or "duration_vs_bytes" in attr_names:
        hypotheses.append({
            "hypothesis": "volumetric_burst_or_data_exfiltration",
            "status": "suspected",
            "trigger_feature": "bytes_per_sec",
            "confidence": 0.80,
            "corroborating_tools": ["analyze_connections", "search_historical_traffic"],
        })
    if "pkts_per_sec" in attr_names:
        hypotheses.append({
            "hypothesis": "denial_of_service_flood",
            "status": "suspected",
            "trigger_feature": "pkts_per_sec",
            "confidence": 0.70,
            "corroborating_tools": ["analyze_connections", "analyze_destination"],
        })
    if not hypotheses:
        hypotheses.append({
            "hypothesis": "statistical_anomaly_unclassified" if score >= 0.6 else "low_score_baseline_check",
            "status": "suspected",
            "trigger_feature": "composite_anomaly_score",
            "confidence": 0.50,
            "corroborating_tools": ["get_network_event", "search_historical_traffic"],
        })
    return hypotheses


def _node_receive(s: Session, state: InvestigationState) -> InvestigationState:
    ev = repo.get_event(s, state["event_id"])
    flow = repo.get_flow(s, ev.flow_id) if ev else None
    flow_dict = {
        "src_ip": flow.src_ip if flow else "unknown",
        "dst_ip": flow.dst_ip if flow else "",
        "src_port": flow.src_port if flow else None,
        "dst_port": flow.dst_port if flow else None,
        "protocol": flow.protocol if flow else None,
        "duration": flow.duration if flow else None,
        "orig_bytes": flow.orig_bytes if flow else 0,
        "resp_bytes": flow.resp_bytes if flow else 0,
        "orig_pkts": flow.orig_pkts if flow else 0,
        "resp_pkts": flow.resp_pkts if flow else 0,
        "features": flow.features if flow else {},
    }
    state["event"] = {
        "event_id": ev.event_id if ev else state["event_id"],
        "flow_id": ev.flow_id if ev else "",
        "anomaly_score": ev.anomaly_score if ev else 0,
        "model_version": ev.model_version if ev else "",
        "status": ev.status if ev else "open",
        "flow": flow_dict,
    }
    state["investigation_log"] = [*state.get("investigation_log", []), f"receive:{state['event_id']}"]
    return state


def _node_initial(s: Session, state: InvestigationState) -> InvestigationState:
    score = float(state.get("event", {}).get("anomaly_score", 0))
    feats = (state.get("event", {}).get("flow") or {}).get("features", {})
    attrs = compute_feature_attributions(feats, score)
    hyps = formulate_hypotheses(attrs, score)
    state["feature_attributions"] = attrs
    state["hypotheses"] = hyps
    state["investigation_log"] = [
        *state.get("investigation_log", []),
        f"initial:score={score} attrs={len(attrs)} hyps={[h['hypothesis'] for h in hyps]}",
    ]
    return state


def _node_tools(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    plan = select_next_tools(state)
    for tool_name, args in plan[:10]:
        result = run_tool(s, inv_id, tool_name, args)
        state["tool_results"] = [*state.get("tool_results", []), {"tool": tool_name, "result": result}]
        state["evidence"] = [*state.get("evidence", []), {"source_tool": tool_name, "payload": result}]
        repo.add_evidence(s, {"evidence_id": f"EV-{uuid.uuid4().hex[:8].upper()}", "investigation_id": inv_id, "source_tool": tool_name, "evidence_type": "graph", "payload": result})
    state["rounds"] = state.get("rounds", 0) + 1
    state["investigation_log"] = [*state.get("investigation_log", []), f"tools:round{state['rounds']} ran={[p[0] for p in plan]}"]
    return state


def validate_hypotheses(hypotheses: list[dict], evidence: list[dict]) -> list[dict]:
    """Test and resolve hypotheses against collected tool evidence."""
    by_tool = {e["source_tool"]: e["payload"] for e in evidence}
    traffic = by_tool.get("analyze_connections", {})
    history = by_tool.get("search_historical_traffic", {})
    dest = by_tool.get("analyze_destination", {})
    net_ev = by_tool.get("get_network_event", {})
    rep = by_tool.get("lookup_reputation", {})

    validated = []
    for hyp in hypotheses:
        h_type = hyp.get("hypothesis")
        h_copy = dict(hyp)

        if h_type == "network_reconnaissance_port_scan":
            scan_like = bool(traffic.get("scan_like"))
            unique_ports = int(traffic.get("unique_dst_ports", 0))
            targeted_ports = dest.get("targeted_ports", [])
            if scan_like or unique_ports >= 10 or len(targeted_ports) >= 5:
                h_copy["status"] = "confirmed"
                h_copy["confidence"] = 0.90
                h_copy["evidence_summary"] = (
                    f"Confirmed via analyze_connections: {unique_ports} unique ports targeted; "
                    f"scan-like pattern identified."
                )
            elif "analyze_connections" in by_tool:
                h_copy["status"] = "refuted"
                h_copy["confidence"] = 0.80
                h_copy["evidence_summary"] = (
                    f"Refuted via analyze_connections: only {unique_ports} port(s) contacted, below scan threshold."
                )
            else:
                h_copy["status"] = "inconclusive"
                h_copy["evidence_summary"] = "Awaiting traffic connection analysis."

        elif h_type == "volumetric_burst_or_data_exfiltration":
            total_bytes = int(traffic.get("total_bytes", 0))
            flow_feats = (net_ev.get("flow") or {}).get("features", {})
            bps = float(flow_feats.get("bytes_per_sec", 0))
            if bps > 20000 or total_bytes > 50000:
                h_copy["status"] = "confirmed"
                h_copy["confidence"] = 0.88
                h_copy["evidence_summary"] = (
                    f"Confirmed via traffic telemetry: {bps:.0f} bytes/sec throughput and {total_bytes} total bytes."
                )
            elif "analyze_connections" in by_tool:
                h_copy["status"] = "refuted"
                h_copy["confidence"] = 0.75
                h_copy["evidence_summary"] = (
                    f"Refuted: traffic volume ({total_bytes} bytes) within standard baseline."
                )
            else:
                h_copy["status"] = "inconclusive"
                h_copy["evidence_summary"] = "Awaiting volumetric traffic data."

        elif h_type == "denial_of_service_flood":
            flow_count = int(traffic.get("flow_count", 0))
            flow_feats = (net_ev.get("flow") or {}).get("features", {})
            pps = float(flow_feats.get("pkts_per_sec", 0))
            if pps > 50 or flow_count >= 50:
                h_copy["status"] = "confirmed"
                h_copy["confidence"] = 0.85
                h_copy["evidence_summary"] = (
                    f"Confirmed via packet telemetry: {pps:.0f} pkts/sec across {flow_count} flows."
                )
            elif "analyze_connections" in by_tool:
                h_copy["status"] = "refuted"
                h_copy["confidence"] = 0.70
                h_copy["evidence_summary"] = (
                    f"Refuted: packet rate ({pps:.0f} pps) and connection count ({flow_count}) below flood thresholds."
                )
            else:
                h_copy["status"] = "inconclusive"
                h_copy["evidence_summary"] = "Awaiting flow connection telemetry."

        elif h_type == "statistical_anomaly_unclassified":
            ev_score = float(net_ev.get("anomaly_score", 0))
            if ev_score >= 0.85:
                h_copy["status"] = "confirmed"
                h_copy["confidence"] = 0.75
                h_copy["evidence_summary"] = (
                    f"Corroborated by high ML anomaly score ({ev_score:.2f}) across multi-feature vector."
                )
            else:
                h_copy["status"] = "inconclusive"
                h_copy["evidence_summary"] = "Baseline traffic anomaly without distinct behavioral signature."

        else:
            h_copy["status"] = "inconclusive"
            h_copy["evidence_summary"] = "Hypothesis under evaluation against collected evidence."

        validated.append(h_copy)
    return validated


def _node_validate(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    ev_list = state.get("evidence", [])
    hyps = state.get("hypotheses", [])
    resolved = validate_hypotheses(hyps, ev_list)
    state["hypotheses"] = resolved
    repo.add_evidence(
        s,
        {
            "evidence_id": f"EV-{uuid.uuid4().hex[:8].upper()}",
            "investigation_id": inv_id,
            "source_tool": "hypothesis_validator",
            "evidence_type": "hypotheses",
            "payload": {"hypotheses": resolved},
        },
    )
    confirmed_names = [h["hypothesis"] for h in resolved if h["status"] == "confirmed"]
    state["investigation_log"] = [
        *state.get("investigation_log", []),
        f"validate:confirmed={confirmed_names or ['none']} total={len(resolved)}",
    ]
    return state


def _node_risk(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    state = assess(state)
    repo.add_evidence(
        s,
        {
            "evidence_id": f"EV-{uuid.uuid4().hex[:8].upper()}",
            "investigation_id": inv_id,
            "source_tool": "risk_assessor",
            "evidence_type": "risk_assessment",
            "payload": state.get("risk_assessment", {}),
        },
    )
    return state


def _need_more(state: InvestigationState) -> bool:
    have = {e["source_tool"] for e in state.get("evidence", [])}
    need = {"get_network_event", "analyze_connections", "search_historical_traffic"} - have
    return bool(need) and state.get("rounds", 0) < 2


def _manual_run(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    state = _node_receive(s, state)
    state = _node_initial(s, state)
    state = _node_tools(s, inv_id, state)
    if _need_more(state):
        state = _node_tools(s, inv_id, state)
    state = _node_validate(s, inv_id, state)
    state = _node_risk(s, inv_id, state)
    return state


def _langgraph_run(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    from langgraph.graph import StateGraph, END

    def n_receive(st: InvestigationState) -> InvestigationState:
        return _node_receive(s, st)

    def n_initial(st: InvestigationState) -> InvestigationState:
        return _node_initial(s, st)

    def n_tools(st: InvestigationState) -> InvestigationState:
        return _node_tools(s, inv_id, st)

    def n_validate(st: InvestigationState) -> InvestigationState:
        return _node_validate(s, inv_id, st)

    def n_risk(st: InvestigationState) -> InvestigationState:
        return _node_risk(s, inv_id, st)

    g = StateGraph(InvestigationState)
    g.add_node("receive", n_receive)
    g.add_node("initial", n_initial)
    g.add_node("tools", n_tools)
    g.add_node("validate", n_validate)
    g.add_node("risk", n_risk)
    g.set_entry_point("receive")
    g.add_edge("receive", "initial")
    g.add_edge("initial", "tools")
    g.add_conditional_edges("tools", lambda st: "tools" if _need_more(st) else "validate")
    g.add_edge("validate", "risk")
    g.add_edge("risk", END)
    return g.compile().invoke(state)


def run_graph_investigation(s: Session, event_id: str) -> str:
    """Entry used by POST /investigations. Creates inv row, runs graph, finishes. Returns inv_id."""
    if not repo.get_event(s, event_id):
        raise ValueError("event not found")
    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    repo.create_investigation(s, {"investigation_id": inv_id, "event_id": event_id, "state": "running"})
    state = fresh_state(event_id)
    try:
        state = _langgraph_run(s, inv_id, state)
    except Exception as e:
        print(f"[agent] langgraph unavailable ({e}), manual fallback")
        state = _manual_run(s, inv_id, state)
    repo.finish_investigation(s, inv_id, outcome="; ".join(state.get("investigation_log", [])[-4:]))
    return inv_id
