"""One-command demo reset: wipe DB + replay 3 flows (normal/monitor/anomaly).

Usage: python scripts/seed.py
Then: uvicorn api.main:app --port 8000
      streamlit run dashboard/app.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DATABASE_URL", "sqlite:///./netsentry.db")

from database.db import engine
from database import models
from fastapi.testclient import TestClient
from api.main import app

FLOW_FILES = ["sample_data/demo_flows.jsonl"]


def main():
    models.Base.metadata.drop_all(bind=engine)
    models.Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    n_events = 0
    with open(FLOW_FILES[0]) as f:
        for line in f:
            flow = json.loads(line)
            out = client.post("/flows/ingest", json=flow).json()
            print(f"{flow['flow_id']} -> score={out['anomaly_score']} pred={out['prediction']} event={out['event_id']}")
            if out["event_id"]:
                n_events += 1
    print(f"seeded 3 flows, {n_events} events. GET /anomalies to investigate.")


if __name__ == "__main__":
    main()
