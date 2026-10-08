"""Deterministic risk assessment — math, not LLM. LLM explains it later."""
from agent.state import InvestigationState


def assess(state: InvestigationState) -> InvestigationState:
    ev = state.get("event", {})
    score = float(ev.get("anomaly_score", 0))
    by_tool = {e["source_tool"]: e["payload"] for e in state.get("evidence", [])}
    traffic = by_tool.get("analyze_connections", {})
    history = by_tool.get("search_historical_traffic", {})
    dest = by_tool.get("analyze_destination", {})
    rep = by_tool.get("lookup_reputation", {})
    sim = by_tool.get("search_similar_incidents", {})
    hypotheses = state.get("hypotheses", [])

    scan_like = bool(traffic.get("scan_like"))
    past_flows = int(history.get("past_flow_count", 99))
    novel = past_flows <= 2
    total_bytes = int(traffic.get("total_bytes") or 0)
    volume = total_bytes > 200000
    high_value_target = bool(dest.get("high_value_target"))
    suspicious_reputation = rep.get("reputation") in ("suspicious", "malicious")
    repeat_offender = bool(sim.get("repeat_offender"))

    # Hypotheses status analysis
    confirmed_hyps = [h for h in hypotheses if h.get("status") == "confirmed"]
    refuted_hyps = [h for h in hypotheses if h.get("status") == "refuted"]

    # Granular factor breakdown matching Report Section 15 specifications
    factor_breakdown = [
        {
            "signal": "ml_anomaly",
            "weight": 0.50,
            "contribution": round(0.50 * score, 3),
            "observed_value": score,
            "description": "Primary detection signal from trained ML feature vector",
            "flagged": score >= 0.60,
        },
        {
            "signal": "port_diversity",
            "weight": 0.20,
            "contribution": 0.20 if scan_like else 0.0,
            "observed_value": f"{traffic.get('unique_dst_ports', 0)} ports (scan_like={scan_like})",
            "description": "Unusual destination port spread indicating horizontal reconnaissance",
            "flagged": scan_like,
        },
        {
            "signal": "historical_novelty",
            "weight": 0.15,
            "contribution": 0.15 if (novel and score >= 0.60) else 0.0,
            "observed_value": f"{past_flows} historical flow(s)",
            "description": "Source IP has little or no baseline history in network telemetry",
            "flagged": novel and score >= 0.60,
        },
        {
            "signal": "volume_burst",
            "weight": 0.15,
            "contribution": 0.15 if volume else 0.0,
            "observed_value": f"{total_bytes} bytes",
            "description": "Volumetric data transfer spike exceeding baseline bandwidth",
            "flagged": volume,
        },
        {
            "signal": "destination_criticality",
            "weight": 0.10,
            "contribution": 0.10 if high_value_target else 0.0,
            "observed_value": f"{dest.get('known_service', 'Unknown')} (Port {dest.get('primary_port', 'n/a')})",
            "description": "Target is identified as an internal critical infrastructure service",
            "flagged": high_value_target,
        },
        {
            "signal": "threat_intelligence",
            "weight": 0.15,
            "contribution": 0.15 if suspicious_reputation else 0.0,
            "observed_value": f"{rep.get('reputation', 'unknown')} ({rep.get('category', 'n/a')})",
            "description": "External or lab threat reputation match on source entity",
            "flagged": suspicious_reputation,
        },
        {
            "signal": "repeat_offender",
            "weight": 0.10,
            "contribution": 0.10 if repeat_offender else 0.0,
            "observed_value": f"{sim.get('prior_incident_count', 0)} prior incidents",
            "description": "Source IP has recurring anomaly records in historical investigations",
            "flagged": repeat_offender,
        },
    ]

    total_risk = sum(f["contribution"] for f in factor_breakdown)
    # If severe hypothesis confirmed, ensure risk meets floor
    if any(h["hypothesis"] in ("network_reconnaissance_port_scan", "volumetric_burst_or_data_exfiltration") for h in confirmed_hyps):
        total_risk = max(total_risk, 0.65)
    total_risk = max(0.0, min(1.0, total_risk))

    level = "low" if total_risk < 0.4 else ("medium" if total_risk < 0.65 else ("high" if total_risk < 0.85 else "critical"))

    # Confidence calibration based on evidence count + hypothesis confirmation
    base_confidence = 0.45 + 0.25 * min(len(state.get("evidence", [])), 5) / 5
    if confirmed_hyps:
        base_confidence += 0.15
    if refuted_hyps and not confirmed_hyps:
        base_confidence -= 0.10
    confidence = round(max(0.2, min(0.95, base_confidence)), 2)

    # Dominant signal determination
    flagged_factors = [f for f in factor_breakdown if f["flagged"]]
    flagged_factors.sort(key=lambda x: x["contribution"], reverse=True)
    dominant_signal = flagged_factors[0]["signal"] if flagged_factors else "baseline_normal"

    # Construct transparent explanation narrative
    reasons = [f"{f['signal']} ({f['contribution']:+.2f})" for f in flagged_factors]
    if confirmed_hyps:
        reasons.append(f"confirmed {len(confirmed_hyps)} hypothesis")
    rationale = f"Risk rating '{level}' ({total_risk:.2f}) driven by: {', '.join(reasons) if reasons else 'nominal traffic'}."

    assessment = {
        "composite_score": round(total_risk, 3),
        "level": level,
        "confidence": confidence,
        "dominant_signal": dominant_signal,
        "rationale": rationale,
        "factor_breakdown": factor_breakdown,
        "hypotheses_evaluated": {
            "confirmed": [h["hypothesis"] for h in confirmed_hyps],
            "refuted": [h["hypothesis"] for h in refuted_hyps],
            "inconclusive": [h["hypothesis"] for h in hypotheses if h.get("status") == "inconclusive"],
        },
    }

    state["risk_level"] = level
    state["risk_factors"] = {f["signal"]: f["contribution"] for f in factor_breakdown}
    state["risk_assessment"] = assessment
    state["confidence"] = confidence
    state["investigation_log"] = [
        *state.get("investigation_log", []),
        f"risk:{level}({total_risk:.2f}) scan={scan_like} novel={novel} dominant={dominant_signal}",
    ]
    return state
