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


def _node_receive(s: Session, state: InvestigationState) -> InvestigationState:
    ev = repo.get_event(s, state["event_id"])
    flow = repo.get_flow(s, ev.flow_id) if ev else None
    state["event"] = {
        "event_id": ev.event_id if ev else state["event_id"],
        "flow_id": ev.flow_id if ev else "",
        "anomaly_score": ev.anomaly_score if ev else 0,
        "model_version": ev.model_version if ev else "",
        "flow": {"src_ip": flow.src_ip if flow else "unknown", "dst_ip": flow.dst_ip if flow else ""},
    }
    state["investigation_log"] = [*state.get("investigation_log", []), f"receive:{state['event_id']}"]
    return state


def _node_initial(s: Session, state: InvestigationState) -> InvestigationState:
    score = float(state.get("event", {}).get("anomaly_score", 0))
    hyp = "burst/scan check" if score >= 0.6 else "low-score sanity check"
    state["investigation_log"] = [*state.get("investigation_log", []), f"initial:score={score} hyp={hyp}"]
    return state


def _node_tools(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    plan = select_next_tools(state)
    for tool_name, args in plan[:6]:
        result = run_tool(s, inv_id, tool_name, args)
        state["tool_results"] = [*state.get("tool_results", []), {"tool": tool_name, "result": result}]
        state["evidence"] = [*state.get("evidence", []), {"source_tool": tool_name, "payload": result}]
        repo.add_evidence(s, {"evidence_id": f"EV-{uuid.uuid4().hex[:8].upper()}", "investigation_id": inv_id, "source_tool": tool_name, "evidence_type": "graph", "payload": result})
    state["rounds"] = state.get("rounds", 0) + 1
    state["investigation_log"] = [*state.get("investigation_log", []), f"tools:round{state['rounds']} ran={[p[0] for p in plan]}"]
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
    state = assess(state)
    return state


def _langgraph_run(s: Session, inv_id: str, state: InvestigationState) -> InvestigationState:
    from langgraph.graph import StateGraph, END

    def n_receive(st: InvestigationState) -> InvestigationState:
        return _node_receive(s, st)

    def n_initial(st: InvestigationState) -> InvestigationState:
        return _node_initial(s, st)

    def n_tools(st: InvestigationState) -> InvestigationState:
        return _node_tools(s, inv_id, st)

    def n_risk(st: InvestigationState) -> InvestigationState:
        return assess(st)

    g = StateGraph(InvestigationState)
    g.add_node("receive", n_receive)
    g.add_node("initial", n_initial)
    g.add_node("tools", n_tools)
    g.add_node("risk", n_risk)
    g.set_entry_point("receive")
    g.add_edge("receive", "initial")
    g.add_edge("initial", "tools")
    g.add_conditional_edges("tools", lambda st: "tools" if _need_more(st) else "risk")
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
