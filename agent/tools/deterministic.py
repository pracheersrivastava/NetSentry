"""Deterministic investigation tools — NO LLM here. Pure DB queries returning facts.

These are the 3 MVP tools from Report Table 6. Agent (LangGraph or stub)
calls them; backend stores raw outputs in tool_calls + evidence.
LLM later only synthesizes these outputs, never invents its own.
"""
import time
import uuid
from sqlalchemy.orm import Session
from database import repository as repo


def _timed(fn, *args, **kwargs):
    t0 = time.time()
    out = fn(*args, **kwargs)
    return out, round(time.time() - t0, 4)


def get_network_event(s: Session, event_id: str) -> dict:
    """Tool 1: retrieve original anomaly metadata + flow record."""
    ev = repo.get_event(s, event_id)
    if not ev:
        return {"error": "event not found"}
    flow = repo.get_flow(s, ev.flow_id)
    return {
        "event_id": ev.event_id,
        "flow_id": ev.flow_id,
        "anomaly_score": ev.anomaly_score,
        "model_version": ev.model_version,
        "status": ev.status,
        "flow": {
            "src_ip": flow.src_ip if flow else None,
            "dst_ip": flow.dst_ip if flow else None,
            "src_port": flow.src_port if flow else None,
            "dst_port": flow.dst_port if flow else None,
            "protocol": flow.protocol if flow else None,
            "duration": flow.duration if flow else None,
            "features": flow.features if flow else {},
        },
    }


def search_historical_traffic(s: Session, src_ip: str, limit: int = 20) -> dict:
    """Tool 2: past behavior from same source — is this novel or recurring?"""
    flows = repo.list_flows(s, limit=limit, src_ip=src_ip)
    return {
        "src_ip": src_ip,
        "past_flow_count": len(flows),
        "past_dst_ports": sorted({f.dst_port for f in flows}),
        "past_dst_ips": sorted({f.dst_ip for f in flows}),
        "sample_flow_ids": [f.flow_id for f in flows[:5]],
    }


def analyze_connections(s: Session, src_ip: str) -> dict:
    """Tool 3: connection volume + destination diversity for a source."""
    flows = repo.list_flows(s, limit=100, src_ip=src_ip)
    dst_ips = {f.dst_ip for f in flows}
    dst_ports = {f.dst_port for f in flows}
    total_bytes = sum((f.features or {}).get("total_bytes", 0) for f in flows) if flows else 0
    return {
        "src_ip": src_ip,
        "flow_count": len(flows),
        "unique_dst_ips": len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "total_bytes": total_bytes,
        "scan_like": len(dst_ports) >= 10 or len(dst_ips) >= 5,
    }


# Registry maps allowlisted tool names -> functions. LLM can ONLY call these.
REGISTRY = {
    "get_network_event": get_network_event,
    "search_historical_traffic": search_historical_traffic,
    "analyze_connections": analyze_connections,
}


def run_tool(s: Session, investigation_id: str, tool_name: str, arguments: dict) -> dict:
    """Execute allowlisted tool, persist tool_calls row, return result for evidence."""
    if tool_name not in REGISTRY:
        raise ValueError(f"tool not allowlisted: {tool_name}")
    result, dt = _timed(REGISTRY[tool_name], s, **arguments)
    repo.add_tool_call(
        s,
        {
            "call_id": f"CALL-{uuid.uuid4().hex[:8].upper()}",
            "investigation_id": investigation_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "result": result,
            "execution_time": dt,
        },
    )
    return result
