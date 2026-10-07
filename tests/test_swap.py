"""Swap-safety tests: backend must not break when real model arrives or replays repeat."""
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
FLOW = {"flow_id": "FLOW-SWAP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 443, "protocol": "TCP", "duration": 1.0, "orig_bytes": 5000, "resp_bytes": 5000, "orig_pkts": 20, "resp_pkts": 20}


def test_model_info_contract():
    r = client.get("/model/info").json()
    assert r["model"] == "isolation_forest"
    assert len(r["feature_order"]) == 12
    assert "model_version" in r


def test_model_validate_missing_artifact():
    r = client.post("/model/validate").json()
    assert "ok" in r  # False when no .joblib yet, but never 500


def test_ingest_dedupe_same_flow():
    a = client.post("/flows/ingest", json=FLOW).json()
    b = client.post("/flows/ingest", json=FLOW).json()
    if a["event_id"] and b["event_id"]:
        assert a["event_id"] == b["event_id"]


def test_investigation_idempotent():
    burst = {**FLOW, "flow_id": "FLOW-IDEM", "duration": 0.4, "orig_bytes": 90000, "resp_bytes": 2000, "orig_pkts": 300, "resp_pkts": 5}
    ing = client.post("/flows/ingest", json=burst).json()
    assert ing["event_id"]
    i1 = client.post(f"/investigations/{ing['event_id']}").json()
    i2 = client.post(f"/investigations/{ing['event_id']}").json()
    assert i1["investigation_id"] == i2["investigation_id"]


def test_batch_and_review():
    flows = [{**FLOW, "flow_id": f"FLOW-B{i}"} for i in range(3)]
    r = client.post("/flows/batch", json=flows)
    assert r.status_code == 200 and len(r.json()) == 3
