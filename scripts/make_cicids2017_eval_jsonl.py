"""Build sample_data/cicids2017_eval.jsonl for detector checks.

CIC-IDS2017 Machine Learning CSVs are not vendored (Kaggle, no source IPs).
This file reconstructs NetSentry ingest records from the same traffic classes
the Isolation Forest was trained and calibrated on: Monday-style benign
enterprise flows, Wednesday-style HTTP floods, Friday-style port scans, and
Tuesday-style SSH brute force. Packet/byte/duration ranges follow the UNB
CICFlowMeter fields described in ml/TRAINING_GUIDE.md.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "sample_data" / "cicids2017_eval.jsonl"
START = datetime(2017, 7, 3, 8, 30, tzinfo=timezone.utc)
RNG = random.Random(2017)


def _ip(prefix: str, lo: int, hi: int) -> str:
    return f"{prefix}.{RNG.randint(lo, hi)}"


def _src_port() -> int:
    return RNG.randint(49152, 65535)


def _pkts_bytes(pkts: int, lo: int, hi: int) -> int:
    return max(0, int(pkts * RNG.randint(lo, hi)))


def benign_web(ts: datetime, n: int) -> dict:
    duration = RNG.uniform(3.0, 90.0)
    orig_pkts = RNG.randint(6, 36)
    resp_pkts = RNG.randint(8, 55)
    return {
        "flow_id": f"FLOW-BENIGN-{n:04d}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "src_ip": _ip("192.168.1", 10, 80),
        "dst_ip": RNG.choice(["10.0.0.25", "10.0.0.26", "10.0.0.80"]),
        "src_port": _src_port(),
        "dst_port": RNG.choice([443, 443, 443, 80, 8080]),
        "protocol": "TCP",
        "duration": round(duration, 3),
        "orig_bytes": _pkts_bytes(orig_pkts, 40, 180),
        "resp_bytes": _pkts_bytes(resp_pkts, 60, 400),
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
    }


def benign_dns(ts: datetime, n: int) -> dict:
    duration = RNG.uniform(0.004, 0.18)
    orig_pkts = RNG.randint(1, 3)
    resp_pkts = RNG.randint(1, 3)
    return {
        "flow_id": f"FLOW-DNS-{n:04d}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "src_ip": _ip("192.168.1", 10, 80),
        "dst_ip": "10.0.0.53",
        "src_port": _src_port(),
        "dst_port": 53,
        "protocol": "UDP",
        "duration": round(duration, 4),
        "orig_bytes": _pkts_bytes(orig_pkts, 40, 90),
        "resp_bytes": _pkts_bytes(resp_pkts, 60, 220),
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
    }


def benign_mail(ts: datetime, n: int) -> dict:
    duration = RNG.uniform(8.0, 120.0)
    orig_pkts = RNG.randint(8, 40)
    resp_pkts = RNG.randint(6, 36)
    return {
        "flow_id": f"FLOW-MAIL-{n:04d}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "src_ip": _ip("192.168.1", 10, 80),
        "dst_ip": "10.0.0.12",
        "src_port": _src_port(),
        "dst_port": RNG.choice([25, 587, 993, 143]),
        "protocol": "TCP",
        "duration": round(duration, 3),
        "orig_bytes": _pkts_bytes(orig_pkts, 60, 350),
        "resp_bytes": _pkts_bytes(resp_pkts, 40, 250),
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
    }


def hulk(ts: datetime, n: int) -> dict:
    duration = RNG.uniform(0.08, 1.8)
    orig_pkts = RNG.randint(180, 900)
    resp_pkts = RNG.randint(1, 12)
    orig_bytes = orig_pkts * RNG.randint(400, 1200)
    return {
        "flow_id": f"FLOW-HULK-{n:04d}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "src_ip": _ip("172.16.0", 10, 60),
        "dst_ip": "10.0.0.25",
        "src_port": _src_port(),
        "dst_port": 80,
        "protocol": "TCP",
        "duration": round(duration, 3),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_pkts * RNG.randint(0, 80),
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
    }


def portscan(ts: datetime, n: int) -> dict:
    duration = RNG.uniform(0.001, 0.04)
    dst_port = (n * 7 + RNG.randint(0, 6)) % 10000 + 1
    return {
        "flow_id": f"FLOW-SCAN-{n:04d}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "src_ip": "192.168.1.77",
        "dst_ip": _ip("10.0.0", 1, 40),
        "src_port": _src_port(),
        "dst_port": dst_port,
        "protocol": "TCP",
        "duration": round(duration, 4),
        "orig_bytes": RNG.choice([0, 40, 44, 60]),
        "resp_bytes": RNG.choice([0, 0, 0, 40]),
        "orig_pkts": 1,
        "resp_pkts": RNG.choice([0, 0, 1]),
    }


def ssh_patator(ts: datetime, n: int) -> dict:
    duration = RNG.uniform(0.2, 4.5)
    orig_pkts = RNG.randint(8, 24)
    resp_pkts = RNG.randint(4, 14)
    return {
        "flow_id": f"FLOW-SSH-{n:04d}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "src_ip": "192.168.1.99",
        "dst_ip": "10.0.0.99",
        "src_port": _src_port(),
        "dst_port": 22,
        "protocol": "TCP",
        "duration": round(duration, 3),
        "orig_bytes": _pkts_bytes(orig_pkts, 40, 90),
        "resp_bytes": _pkts_bytes(resp_pkts, 40, 80),
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
    }


def main() -> None:
    plan: list[tuple[str, int]] = (
        [("web", 1) for _ in range(1400)]
        + [("dns", 1) for _ in range(280)]
        + [("mail", 1) for _ in range(120)]
        + [("hulk", 1) for _ in range(120)]
        + [("scan", 1) for _ in range(200)]
        + [("ssh", 1) for _ in range(80)]
    )
    RNG.shuffle(plan)
    counts = {"web": 0, "dns": 0, "mail": 0, "hulk": 0, "scan": 0, "ssh": 0}
    builders = {
        "web": benign_web,
        "dns": benign_dns,
        "mail": benign_mail,
        "hulk": hulk,
        "scan": portscan,
        "ssh": ssh_patator,
    }
    ts = START
    rows = []
    for kind, _ in plan:
        counts[kind] += 1
        ts = ts + timedelta(milliseconds=RNG.randint(40, 1800))
        rows.append(builders[kind](ts, counts[kind]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=(", ", ": ")) + "\n")
    print(f"wrote {len(rows)} flows to {OUT}")
    print("mix:", {k: v for k, v in counts.items()})


if __name__ == "__main__":
    main()
