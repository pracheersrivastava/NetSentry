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
    ap.add_argument("--chunk", type=int, default=500)
    args = ap.parse_args()
    flows = [json.loads(line) for line in open(args.file) if line.strip()]
    scored, events = 0, 0
    for i in range(0, len(flows), args.chunk):
        batch = flows[i : i + args.chunk]
        out = post(f"{args.api}/flows/batch", batch)
        for flow, result in zip(batch, out):
            scored += 1
            if result.get("event_id"):
                events += 1
            print(
                f"{result['flow_id']} -> score={result['anomaly_score']} "
                f"pred={result['prediction']} event={result['event_id']}"
            )
    print(f"done. {scored} flows scored, {events} anomaly events created.")


if __name__ == "__main__":
    main()
