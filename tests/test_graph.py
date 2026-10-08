"""Graph test: LangGraph runner produces same 3-tool evidence + risk in outcome."""
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
BURST = {"flow_id": "FLOW-G1", "src_ip": "192.168.1.99", "dst_ip": "10.0.0.25", "src_port": 44001, "dst_port": 80, "protocol": "TCP", "duration": 0.4, "orig_bytes": 90000, "resp_bytes": 2000, "orig_pkts": 300, "resp_pkts": 5}


def test_graph_investigation():
    ing = client.post("/flows/ingest", json=BURST).json()
    assert ing["event_id"]
    inv = client.post(f"/investigations/{ing['event_id']}").json()
    assert inv["state"] == "done", inv
    assert "risk:" in (inv["outcome"] or ""), inv
    ev = client.get(f"/investigations/{inv['investigation_id']}/evidence").json()
    assert {e["source_tool"] for e in ev} == {"get_network_event", "search_historical_traffic", "analyze_connections"}
