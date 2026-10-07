"""PCAP reader shim for demo: tries scapy if installed, else instructs to use JSONL replay.

MVP demo path uses JsonlFlowSource (no root/libpcap needed).
When team is ready for live: implement LiveSource here with scapy.sniff() yielding FlowIn dicts.
"""
try:
    from scapy.all import rdpcap  # type: ignore

    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


def read_pcap(path: str):
    if not HAS_SCAPY:
        raise RuntimeError("scapy not installed; use sample_data/demo_flows.jsonl replay for demo (see scripts/demo_replay.py)")
    pkts = rdpcap(path)
    # Full packet->flow grouping is Phase 2; for now yield raw summaries.
    for p in pkts:
        yield {"summary": p.summary()}
