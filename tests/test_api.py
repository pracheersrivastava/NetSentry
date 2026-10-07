"""Smoke tests: stub scoring + thresholding + API round-trip (no sklearn/scapy needed)."""
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

BENIGN = {"flow_id": "FLOW-T1", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.25", "src_port": 50001, "dst_port": 443, "protocol": "TCP", "duration": 2.0, "orig_bytes": 2000, "resp_bytes": 3000, "orig_pkts": 10, "resp_pkts": 10}
BURST = {"flow_id": "FLOW-T2", "src_ip": "192.168.1.99", "dst_ip": "10.0.0.25", "src_port": 44001, "dst_port": 80, "protocol": "TCP", "duration": 0.4, "orig_bytes": 90000, "resp_bytes": 2000, "orig_pkts": 300, "resp_pkts": 5}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_predict_benign_low_score():
    r = client.post("/model/predict", json=BENIGN)
    assert r.status_code == 200, r.text
    assert r.json()["anomaly_score"] < 0.6


def test_ingest_burst_creates_event():
    r = client.post("/flows/ingest", json=BURST)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["prediction"] == "anomaly"
    assert body["event_id"] is not None
    ev = client.get("/anomalies").json()
    assert any(e["event_id"] == body["event_id"] for e in ev)
