"""Demo replay: script-based monitoring (no live NIC). Replays JSONL flows into backend.

Usage:
  uvicorn api.main:app --port 8000        # terminal 1
  python scripts/demo_replay.py --api http://localhost:8000 --file sample_data/demo_flows.jsonl
"""
import argparse
import json
import urllib.request


def post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--file", default="sample_data/demo_flows.jsonl")
    args = ap.parse_args()
    with open(args.file) as f:
        for line in f:
            flow = json.loads(line)
            out = post(f"{args.api}/flows/ingest", flow)
            print(f"{flow['flow_id']} -> score={out['anomaly_score']} pred={out['prediction']} event={out['event_id']}")
    print("done. Check GET /flows and GET /anomalies in browser/docs.")


if __name__ == "__main__":
    main()
