"""Contracts required by the React analyst console."""
from fastapi.testclient import TestClient
from api.main import app


def test_flow_details_include_time_and_current_score():
    flow = {
        "flow_id": "FLOW-CONSOLE-CONTRACT", "timestamp": "2026-10-08T12:00:00Z",
        "src_ip": "192.168.1.88", "dst_ip": "10.0.0.25",
        "src_port": 44001, "dst_port": 80, "protocol": "TCP",
        "duration": 0.4, "orig_bytes": 90000, "resp_bytes": 2000,
        "orig_pkts": 300, "resp_pkts": 5,
    }
    with TestClient(app) as client:
        ingested = client.post("/flows/ingest", json=flow).json()
        detail = client.get(f"/flows/{flow['flow_id']}").json()
        assert detail["timestamp"].startswith("2026-10-08T12:00:00")
        assert detail["anomaly_score"] == ingested["anomaly_score"]
        listing = client.get("/flows?limit=500").json()
        assert any(f["flow_id"] == flow["flow_id"] and "timestamp" in f for f in listing)
        assert client.get("/flows?limit=501").status_code == 422
        assert client.get("/flows?offset=-1").status_code == 422


def test_thresholds_and_initial_analysis_are_exposed():
    with TestClient(app) as client:
        policy = client.get("/model/info").json()["thresholds"]
        assert 0 <= policy["monitor_at"] < policy["investigate_at"] <= 1
        flow = {
            "flow_id": "FLOW-CONSOLE-EVIDENCE", "src_ip": "192.168.1.89",
            "dst_ip": "10.0.0.25", "src_port": 44002, "dst_port": 80,
            "duration": 0.4, "orig_bytes": 90000, "resp_bytes": 2000,
            "orig_pkts": 300, "resp_pkts": 5,
        }
        event = client.post("/flows/ingest", json=flow).json()["event_id"]
        inv = client.post(f"/investigations/{event}").json()
        evidence = client.get(f"/investigations/{inv['investigation_id']}/evidence").json()
        analysis = [e for e in evidence if e["source_tool"] == "feature_attribution"]
        assert len(analysis) == 1
        assert analysis[0]["payload"]["attributions"]
        assert analysis[0]["payload"]["hypotheses"]
        assert client.post(f"/investigations/{event}").json()["investigation_id"] == inv["investigation_id"]
