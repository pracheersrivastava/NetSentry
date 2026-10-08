"""Tests for deterministic investigation tools, feature attribution, and hypothesis formulation."""
from fastapi.testclient import TestClient
from api.main import app
from database.db import SessionLocal
from agent.tools.deterministic import (
    REGISTRY,
    analyze_destination,
    search_similar_incidents,
    lookup_dns,
    lookup_reputation,
)
from agent.graph import compute_feature_attributions, formulate_hypotheses

client = TestClient(app)

BURST_FLOW = {
    "flow_id": "FLOW-TOOL-TEST",
    "src_ip": "192.168.1.99",
    "dst_ip": "10.0.0.25",
    "src_port": 44001,
    "dst_port": 443,
    "protocol": "TCP",
    "duration": 0.4,
    "orig_bytes": 90000,
    "resp_bytes": 2000,
    "orig_pkts": 300,
    "resp_pkts": 5,
}


def test_registry_contains_all_seven_tools():
    expected_tools = {
        "get_network_event",
        "search_historical_traffic",
        "analyze_connections",
        "analyze_destination",
        "search_similar_incidents",
        "lookup_dns",
        "lookup_reputation",
    }
    assert expected_tools.issubset(set(REGISTRY.keys()))


def test_analyze_destination_tool():
    db = SessionLocal()
    try:
        # Ingest test flow first
        client.post("/flows/ingest", json=BURST_FLOW)
        res = analyze_destination(db, dst_ip="10.0.0.25", dst_port=443)
        assert res["dst_ip"] == "10.0.0.25"
        assert res["is_internal"] is True
        assert res["known_service"] == "HTTPS"
        assert res["inbound_flow_count"] >= 1
    finally:
        db.close()


def test_lookup_dns_tool():
    db = SessionLocal()
    try:
        res = lookup_dns(db, "10.0.0.25")
        assert res["query"] == "10.0.0.25"
        assert res["is_internal"] is True
        assert "core-api-server" in res["resolved_name"]

        res_unknown = lookup_dns(db, "192.168.100.50")
        assert res_unknown["dns_status"] in ("resolved", "heuristic_default")
    finally:
        db.close()


def test_lookup_reputation_tool():
    db = SessionLocal()
    try:
        # Known lab threat
        res_threat = lookup_reputation(db, "192.168.1.99")
        assert res_threat["reputation"] == "suspicious"
        assert res_threat["threat_score"] > 0.5
        assert "high_conn_rate" in res_threat["indicators_matched"]

        # Neutral internal
        res_internal = lookup_reputation(db, "10.0.0.25")
        assert res_internal["reputation"] == "neutral_internal"
        assert res_internal["threat_score"] == 0.0
    finally:
        db.close()


def test_search_similar_incidents_tool():
    db = SessionLocal()
    try:
        res = search_similar_incidents(db, "192.168.1.99")
        assert "src_ip" in res
        assert "prior_incident_count" in res
        assert isinstance(res["prior_incidents"], list)
    finally:
        db.close()


def test_feature_attributions_and_hypotheses():
    burst_features = {
        "bytes_per_sec": 225000.0,
        "pkts_per_sec": 750.0,
        "unique_dst_ports_5min": 1,
        "failed_conn_ratio_5min": 0.0,
        "total_bytes": 92000,
        "duration": 0.4,
    }
    attrs = compute_feature_attributions(burst_features, score=0.92)
    attr_names = {a["feature"] for a in attrs}
    assert "bytes_per_sec" in attr_names
    assert "pkts_per_sec" in attr_names
    assert "duration_vs_bytes" in attr_names

    hyps = formulate_hypotheses(attrs, score=0.92)
    hyp_names = {h["hypothesis"] for h in hyps}
    assert "volumetric_burst_or_data_exfiltration" in hyp_names
    assert "denial_of_service_flood" in hyp_names


def test_port_scan_feature_attribution():
    scan_features = {
        "bytes_per_sec": 5000.0,
        "pkts_per_sec": 10.0,
        "unique_dst_ports_5min": 25,
        "failed_conn_ratio_5min": 0.5,
        "total_bytes": 2000,
        "duration": 2.0,
    }
    attrs = compute_feature_attributions(scan_features, score=0.88)
    hyps = formulate_hypotheses(attrs, score=0.88)
    hyp_names = {h["hypothesis"] for h in hyps}
    assert "network_reconnaissance_port_scan" in hyp_names


def test_validate_hypotheses_resolution():
    from agent.graph import validate_hypotheses

    hyps = [
        {"hypothesis": "network_reconnaissance_port_scan", "status": "suspected", "trigger_feature": "unique_dst_ports_5min"},
        {"hypothesis": "volumetric_burst_or_data_exfiltration", "status": "suspected", "trigger_feature": "bytes_per_sec"},
    ]
    mock_evidence = [
        {"source_tool": "analyze_connections", "payload": {"scan_like": True, "unique_dst_ports": 18, "total_bytes": 120000}},
        {"source_tool": "get_network_event", "payload": {"flow": {"features": {"bytes_per_sec": 65000}}}},
    ]
    resolved = validate_hypotheses(hyps, mock_evidence)
    by_name = {h["hypothesis"]: h for h in resolved}

    assert by_name["network_reconnaissance_port_scan"]["status"] == "confirmed"
    assert "scan-like" in by_name["network_reconnaissance_port_scan"]["evidence_summary"]

    assert by_name["volumetric_burst_or_data_exfiltration"]["status"] == "confirmed"
    assert "throughput" in by_name["volumetric_burst_or_data_exfiltration"]["evidence_summary"]


def test_transparent_risk_assessment_breakdown():
    from agent.risk import assess
    from agent.state import fresh_state

    st = fresh_state("ANM-TEST-RISK")
    st["event"] = {"anomaly_score": 0.88}
    st["hypotheses"] = [{"hypothesis": "network_reconnaissance_port_scan", "status": "confirmed"}]
    st["evidence"] = [
        {"source_tool": "analyze_connections", "payload": {"scan_like": True, "unique_dst_ports": 15, "total_bytes": 250000}},
        {"source_tool": "search_historical_traffic", "payload": {"past_flow_count": 1}},
        {"source_tool": "analyze_destination", "payload": {"high_value_target": True, "known_service": "SSH", "primary_port": 22}},
        {"source_tool": "lookup_reputation", "payload": {"reputation": "suspicious", "category": "Lab Attack Generator"}},
        {"source_tool": "search_similar_incidents", "payload": {"repeat_offender": True, "prior_incident_count": 3}},
    ]

    out_state = assess(st)
    assert out_state["risk_level"] in ("high", "critical")
    risk_obj = out_state["risk_assessment"]

    assert "composite_score" in risk_obj
    assert risk_obj["composite_score"] >= 0.70
    assert "rationale" in risk_obj
    assert "factor_breakdown" in risk_obj
    assert len(risk_obj["factor_breakdown"]) == 7

    flagged_signals = {f["signal"] for f in risk_obj["factor_breakdown"] if f["flagged"]}
    assert "ml_anomaly" in flagged_signals
    assert "port_diversity" in flagged_signals
    assert "historical_novelty" in flagged_signals
    assert "destination_criticality" in flagged_signals


def test_end_to_end_investigation_hypotheses_and_risk():
    import uuid
    burst = {
        "flow_id": f"FLOW-E2E-{uuid.uuid4().hex[:6]}",
        "src_ip": "192.168.1.99",
        "dst_ip": "10.0.0.25",
        "src_port": 44001,
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 0.4,
        "orig_bytes": 90000,
        "resp_bytes": 2000,
        "orig_pkts": 300,
        "resp_pkts": 5,
    }
    ing = client.post("/flows/ingest", json=burst).json()
    assert ing["event_id"]

    inv = client.post(f"/investigations/{ing['event_id']}").json()
    assert inv["state"] == "done"

    # Verify report contains hypotheses, risk_assessment, and mitre_techniques
    rep = client.get(f"/reports/{inv['investigation_id']}").json()
    rj = rep["report_json"]
    assert "hypotheses" in rj
    assert "risk_assessment" in rj
    assert "mitre_techniques" in rj
    assert rj["risk_assessment"]["composite_score"] > 0
    assert rj["confidence"] > 0.5


def test_mitre_attack_mapping_and_prompt_template():
    from agent.prompts import MITRE_TAXONOMY, SYNTHESIS_PROMPT_TEMPLATE
    from reports.generator import build_report

    assert "port_scan" in MITRE_TAXONOMY
    assert MITRE_TAXONOMY["port_scan"]["id"] == "T1046"

    # Test template formatting
    formatted = SYNTHESIS_PROMPT_TEMPLATE.format(
        event_json='{"event_id": "TEST"}',
        evidence_json='[{"tool": "analyze_connections"}]'
    )
    assert "T1046" in formatted
    assert "STRICT GROUNDING RULES" in formatted

    # Test deterministic report generator includes mitre_techniques
    mock_ev = [
        {"source_tool": "analyze_connections", "payload": {"scan_like": True, "unique_dst_ports": 12}},
        {"source_tool": "get_network_event", "payload": {"flow": {"features": {"bytes_per_sec": 75000}}}},
        {"source_tool": "lookup_reputation", "payload": {"reputation": "suspicious"}},
    ]
    rep = build_report({"event_id": "ANM-M1", "anomaly_score": 0.9}, mock_ev)
    mitre_ids = {m["id"] for m in rep.get("mitre_techniques", [])}
    assert "T1046" in mitre_ids
    assert "T1048" in mitre_ids


