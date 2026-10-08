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


def analyze_destination(s: Session, dst_ip: str, dst_port: int | None = None) -> dict:
    """Tool 4: destination host telemetry, inbound connections, service mapping."""
    import ipaddress

    flows = s.query(repo.models.NetworkFlow).filter(repo.models.NetworkFlow.dst_ip == dst_ip).limit(100).all()
    unique_srcs = {f.src_ip for f in flows}
    targeted_ports = sorted({f.dst_port for f in flows if f.dst_port is not None})
    total_orig_bytes = sum(f.orig_bytes or 0 for f in flows)

    is_internal = False
    try:
        is_internal = ipaddress.ip_address(dst_ip).is_private
    except ValueError:
        pass

    service_map = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        53: "DNS",
        3389: "RDP",
        445: "SMB",
        21: "FTP",
        25: "SMTP",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy/Alt",
    }
    primary_port = dst_port if dst_port is not None else (targeted_ports[0] if targeted_ports else None)
    known_service = service_map.get(primary_port, f"Port {primary_port}" if primary_port else "Unknown")
    is_high_value = bool(primary_port in (22, 3389, 445, 3306, 5432) or len(unique_srcs) >= 5)

    return {
        "dst_ip": dst_ip,
        "is_internal": is_internal,
        "primary_port": primary_port,
        "known_service": known_service,
        "inbound_flow_count": len(flows),
        "unique_sources_count": len(unique_srcs),
        "targeted_ports": targeted_ports,
        "total_inbound_bytes": total_orig_bytes,
        "high_value_target": is_high_value,
    }


def search_similar_incidents(s: Session, src_ip: str, limit: int = 5) -> dict:
    """Tool 5: cross-incident correlation — check prior anomaly events and analyst reviews for this source."""
    events = (
        s.query(repo.models.AnomalyEvent)
        .join(repo.models.NetworkFlow, repo.models.AnomalyEvent.flow_id == repo.models.NetworkFlow.flow_id)
        .filter(repo.models.NetworkFlow.src_ip == src_ip)
        .order_by(repo.models.AnomalyEvent.created_at.desc())
        .limit(limit)
        .all()
    )

    incidents = []
    for ev in events:
        inv = repo.get_investigation_by_event(s, ev.event_id)
        rep = repo.get_report_by_investigation(s, inv.investigation_id) if inv else None
        incidents.append(
            {
                "event_id": ev.event_id,
                "anomaly_score": ev.anomaly_score,
                "status": ev.status,
                "investigation_id": inv.investigation_id if inv else None,
                "reviewer_status": rep.reviewer_status if rep else "none",
                "outcome": inv.outcome if inv else None,
            }
        )

    known_fp = any(inc["reviewer_status"] == "rejected" for inc in incidents)
    repeat_offender = len(incidents) >= 2

    return {
        "src_ip": src_ip,
        "prior_incident_count": len(incidents),
        "prior_incidents": incidents,
        "known_false_positive": known_fp,
        "repeat_offender": repeat_offender,
    }


def lookup_dns(s: Session, domain_or_ip: str) -> dict:
    """Tool 6: DNS/host context lookup (offline/lab safe with PTR/A heuristic)."""
    import ipaddress
    import socket

    LAB_HOSTS = {
        "192.168.1.10": "client-workstation-alpha.lab",
        "192.168.1.99": "threat-sim-burst-99.lab",
        "10.0.0.25": "core-api-server.internal",
        "10.0.0.1": "gateway-router.internal",
        "127.0.0.1": "localhost",
    }

    is_ip = False
    is_internal = False
    try:
        addr = ipaddress.ip_address(domain_or_ip)
        is_ip = True
        is_internal = addr.is_private
    except ValueError:
        pass

    resolved_name = LAB_HOSTS.get(domain_or_ip)
    dns_status = "resolved" if resolved_name else "unresolved"

    if not resolved_name and is_ip:
        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(0.5)
            resolved_name = socket.gethostbyaddr(domain_or_ip)[0]
            dns_status = "resolved"
        except Exception:
            resolved_name = f"ip-{domain_or_ip.replace('.', '-')}.{'internal' if is_internal else 'net'}"
            dns_status = "heuristic_default"
        finally:
            socket.setdefaulttimeout(orig_timeout)

    return {
        "query": domain_or_ip,
        "is_ip": is_ip,
        "is_internal": is_internal,
        "resolved_name": resolved_name,
        "dns_status": dns_status,
        "record_type": "PTR" if is_ip else "A",
    }


def lookup_reputation(s: Session, indicator: str) -> dict:
    """Tool 7: Threat intelligence lookup (deterministic feed, no external API quota burn)."""
    import ipaddress

    is_private = False
    try:
        is_private = ipaddress.ip_address(indicator).is_private
    except ValueError:
        pass

    KNOWN_THREATS = {
        "192.168.1.99": {
            "reputation": "suspicious",
            "threat_score": 0.75,
            "category": "Lab Attack Generator / High-Rate Burst",
            "indicators": ["high_conn_rate", "abnormal_packet_burst"],
        },
        "185.220.101.5": {
            "reputation": "malicious",
            "threat_score": 0.95,
            "category": "Known Tor Exit Relay / C2 Scanner",
            "indicators": ["tor_exit", "port_sweep"],
        },
    }

    if indicator in KNOWN_THREATS:
        threat_info = KNOWN_THREATS[indicator]
        return {
            "indicator": indicator,
            "reputation": threat_info["reputation"],
            "threat_score": threat_info["threat_score"],
            "category": threat_info["category"],
            "indicators_matched": threat_info["indicators"],
            "feed_source": "NetSentry Deterministic Threat Feed v1.0",
        }

    if is_private:
        return {
            "indicator": indicator,
            "reputation": "neutral_internal",
            "threat_score": 0.0,
            "category": "RFC1918 Private Asset",
            "indicators_matched": [],
            "feed_source": "NetSentry Deterministic Threat Feed v1.0",
        }

    return {
        "indicator": indicator,
        "reputation": "unknown_external",
        "threat_score": 0.15,
        "category": "Unindexed External IP",
        "indicators_matched": [],
        "feed_source": "NetSentry Deterministic Threat Feed v1.0",
    }


# Registry maps allowlisted tool names -> functions. LLM can ONLY call these.
REGISTRY = {
    "get_network_event": get_network_event,
    "search_historical_traffic": search_historical_traffic,
    "analyze_connections": analyze_connections,
    "analyze_destination": analyze_destination,
    "search_similar_incidents": search_similar_incidents,
    "lookup_dns": lookup_dns,
    "lookup_reputation": lookup_reputation,
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
