"""Report builder — JSON first (machine-readable), Markdown second.

Stub synthesis today (rule-based from evidence). LLM team replaces
synthesize_findings() with evidence-grounded prompt later; schema stays frozen.
"""
import uuid


def _severity(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def build_report(event: dict, evidence: list[dict]) -> dict:
    by_tool = {e["source_tool"]: e["payload"] for e in evidence}
    traffic = by_tool.get("analyze_connections", {})
    history = by_tool.get("search_historical_traffic", {})
    net_ev = by_tool.get("get_network_event", {})
    score = float(event.get("anomaly_score", 0))
    bps = (net_ev.get("flow") or {}).get("features", {}).get("bytes_per_sec", 0)

    observed = [
        f"flow {event.get('flow_id')} scored {score} ({event.get('model_version')})",
        f"source {traffic.get('src_ip')} made {traffic.get('flow_count', 0)} flows to {traffic.get('unique_dst_ips', 0)} dst IPs / {traffic.get('unique_dst_ports', 0)} ports",
        f"history: {history.get('past_flow_count', 0)} past flows from source",
    ]
    findings = []
    if bps and bps > 50000:
        findings.append(f"high-volume burst observed: {bps:.0f} bytes/sec in triggering flow (observed, not proven malicious)")
    if traffic.get("scan_like"):
        findings.append("port/host diversity suggests scan-like behavior (observed, not proven malicious)")
    if score >= 0.85 and history.get("past_flow_count", 0) <= 2:
        findings.append("novel behavior vs limited history — prioritize review")
    if not findings:
        findings.append("no corroborating burst/scan signals in 3-tool MVP set")

    return {
        "incident_id": event.get("event_id"),
        "severity": _severity(score),
        "anomaly_score": score,
        "observed_facts": observed,
        "evidence": evidence,
        "findings": findings,
        "confidence": 0.65 if score >= 0.85 else 0.4,
        "uncertainties": ["stub synthesis: no LLM, no DNS/threat-intel yet", "encrypted payloads not inspected"],
        "recommended_next_steps": ["review evidence in dashboard", "re-run with historical window", "wire LLM synthesis"],
        "tool_trace": [e["source_tool"] for e in evidence],
    }


def new_report_doc(investigation_id: str, report_json: dict) -> dict:
    return {
        "report_id": f"RPT-{uuid.uuid4().hex[:8].upper()}",
        "investigation_id": investigation_id,
        "report_json": report_json,
        "reviewer_status": "pending",
    }
