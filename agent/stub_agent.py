"""Stub investigator: deterministic stand-in for LangGraph+LLM.

Runs the 3 MVP tools in fixed order, stores evidence rows, finishes investigation.
Real agent later replaces synthesize() with LangGraph graph + LLM call —
tool outputs + DB rows stay identical, so backend/dashboard don't change.
"""
import uuid
from sqlalchemy.orm import Session
from database import repository as repo
from agent.tools.deterministic import run_tool


def run_stub_investigation(s: Session, event_id: str) -> str:
    ev = repo.get_event(s, event_id)
    if not ev:
        raise ValueError("event not found")
    inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    repo.create_investigation(s, {"investigation_id": inv_id, "event_id": event_id, "state": "running"})

    flow = repo.get_flow(s, ev.flow_id)
    src_ip = flow.src_ip if flow else "unknown"

    # Fixed evidence plan (agent team makes this dynamic later via LangGraph)
    plan = [
        ("get_network_event", {"event_id": event_id}, "event", "lookup"),
        ("search_historical_traffic", {"src_ip": src_ip}, "history", "baseline"),
        ("analyze_connections", {"src_ip": src_ip}, "traffic", "stats"),
    ]
    for tool_name, args, ev_type, _label in plan:
        result = run_tool(s, inv_id, tool_name, args)
        repo.add_evidence(
            s,
            {
                "evidence_id": f"EV-{uuid.uuid4().hex[:8].upper()}",
                "investigation_id": inv_id,
                "source_tool": tool_name,
                "evidence_type": ev_type,
                "payload": result,
            },
        )

    repo.finish_investigation(s, inv_id, outcome="stub-complete: 3/3 tools, awaiting LLM synthesis")
    return inv_id
