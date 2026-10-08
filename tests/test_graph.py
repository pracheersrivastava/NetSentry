import uuid
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_graph_investigation():
    burst = {
        "flow_id": f"FLOW-G-{uuid.uuid4().hex[:6]}",
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
    assert inv["state"] == "done", inv
    assert "risk:" in (inv["outcome"] or ""), inv
    ev = client.get(f"/investigations/{inv['investigation_id']}/evidence").json()
    tools = {e["source_tool"] for e in ev}
    assert {"get_network_event", "search_historical_traffic", "analyze_connections"}.issubset(tools)
    assert {"analyze_destination", "lookup_reputation"}.issubset(tools)
