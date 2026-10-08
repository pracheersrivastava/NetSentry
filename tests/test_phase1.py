"""Phase 1 test: ingest burst -> investigate (3 tools) -> evidence -> report."""
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
BURST = {"flow_id": "FLOW-P1", "src_ip": "192.168.1.99", "dst_ip": "10.0.0.25", "src_port": 44001, "dst_port": 80, "protocol": "TCP", "duration": 0.4, "orig_bytes": 90000, "resp_bytes": 2000, "orig_pkts": 300, "resp_pkts": 5}


def test_phase1_full_chain():
    ing = client.post("/flows/ingest", json=BURST).json()
    assert ing["event_id"], ing
    inv = client.post(f"/investigations/{ing['event_id']}").json()
    assert inv["state"] == "done", inv
    ev = client.get(f"/investigations/{inv['investigation_id']}/evidence").json()
    tools = {e["source_tool"] for e in ev}
    assert {"get_network_event", "search_historical_traffic", "analyze_connections"}.issubset(tools), ev
    # report auto-created; fetch via investigation id convenience lookup
    rep = client.get(f"/reports/{inv['investigation_id']}").json()
    assert rep["report_json"]["incident_id"] == ing["event_id"]
    assert "observed_facts" in rep["report_json"]
