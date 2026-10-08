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
    dest = by_tool.get("analyze_destination", {})
    rep = by_tool.get("lookup_reputation", {})
    dns = by_tool.get("lookup_dns", {})
    sim = by_tool.get("search_similar_incidents", {})
    score = float(event.get("anomaly_score", 0))
    bps = (net_ev.get("flow") or {}).get("features", {}).get("bytes_per_sec", 0)

    observed = [
        f"flow {event.get('flow_id')} scored {score} ({event.get('model_version')})",
        f"source {traffic.get('src_ip')} made {traffic.get('flow_count', 0)} flows to {traffic.get('unique_dst_ips', 0)} dst IPs / {traffic.get('unique_dst_ports', 0)} ports",
        f"history: {history.get('past_flow_count', 0)} past flows from source",
    ]
    if dest and dest.get("dst_ip"):
        observed.append(f"target host {dest.get('dst_ip')} identified as service {dest.get('known_service')} (port {dest.get('primary_port')})")
    if rep and rep.get("indicator"):
        observed.append(f"reputation lookup: source {rep.get('indicator')} marked {rep.get('reputation')} ({rep.get('category')})")
    if dns and dns.get("resolved_name"):
        observed.append(f"DNS resolution: {dns.get('query')} -> {dns.get('resolved_name')}")
    if sim and sim.get("prior_incident_count", 0) > 0:
        observed.append(f"prior incidents: {sim.get('prior_incident_count')} previous anomaly events recorded for source")

    findings = []
    if bps and bps > 50000:
        findings.append(f"high-volume burst observed: {bps:.0f} bytes/sec in triggering flow (observed, not proven malicious)")
    if traffic.get("scan_like"):
        findings.append("port/host diversity suggests scan-like behavior (observed, not proven malicious)")
    if score >= 0.85 and history.get("past_flow_count", 0) <= 2:
        findings.append("novel behavior vs limited history — prioritize review")
    if rep and rep.get("reputation") in ("suspicious", "malicious"):
        findings.append(f"threat intelligence corroboration: source flagged in threat registry as {rep.get('category')}")
    if dest and dest.get("high_value_target"):
        findings.append(f"target asset {dest.get('dst_ip')} is designated high-value service ({dest.get('known_service')})")
    if sim and sim.get("repeat_offender"):
        findings.append("source IP exhibits repeat anomalous activity across multiple recorded incidents")
    if not findings:
        findings.append("no corroborating burst/scan signals in tool set")

    hyp_data = by_tool.get("hypothesis_validator", {})
    risk_data = by_tool.get("risk_assessor", {})
    resolved_hyps = hyp_data.get("hypotheses", [])
    for h in resolved_hyps:
        if h.get("status") == "confirmed":
            findings.append(f"Hypothesis confirmed: {h.get('hypothesis')} — {h.get('evidence_summary', '')}")
        elif h.get("status") == "refuted":
            observed.append(f"Hypothesis refuted: {h.get('hypothesis')} — {h.get('evidence_summary', '')}")

    mitre_techniques = []
    if traffic.get("scan_like") or any(h.get("hypothesis") == "network_reconnaissance_port_scan" and h.get("status") == "confirmed" for h in resolved_hyps):
        mitre_techniques.append({"id": "T1046", "name": "Network Service Discovery", "tactic": "Reconnaissance"})
    if (bps and bps > 50000) or any(h.get("hypothesis") == "volumetric_burst_or_data_exfiltration" and h.get("status") == "confirmed" for h in resolved_hyps):
        mitre_techniques.append({"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"})
    if any(h.get("hypothesis") == "denial_of_service_flood" and h.get("status") == "confirmed" for h in resolved_hyps):
        mitre_techniques.append({"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"})
    if rep and rep.get("reputation") in ("suspicious", "malicious"):
        mitre_techniques.append({"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"})

    uncertainties = ["encrypted payloads not inspected (TLS/HTTPS metadata only)"]
    if not rep:
        uncertainties.append("threat intelligence feed not queried")
    if not dns:
        uncertainties.append("DNS telemetry not resolved")

    confidence = risk_data.get("confidence") or (0.75 if (score >= 0.85 and len(evidence) >= 5) else (0.65 if score >= 0.85 else 0.4))

    return {
        "incident_id": event.get("event_id"),
        "severity": _severity(score),
        "anomaly_score": score,
        "observed_facts": observed,
        "evidence": evidence,
        "findings": findings,
        "hypotheses": resolved_hyps,
        "risk_assessment": risk_data,
        "mitre_techniques": mitre_techniques,
        "confidence": confidence,
        "uncertainties": uncertainties,
        "recommended_next_steps": ["review evidence in dashboard", "verify destination host logs", "check for active egress"],
        "tool_trace": [e["source_tool"] for e in evidence],
    }


def new_report_doc(investigation_id: str, report_json: dict) -> dict:
    return {
        "report_id": f"RPT-{uuid.uuid4().hex[:8].upper()}",
        "investigation_id": investigation_id,
        "report_json": report_json,
        "reviewer_status": "pending",
    }
