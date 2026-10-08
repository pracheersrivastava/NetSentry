"""Script replay source: reads JSONL flows (demo.pcap equivalent without libpcap).

Later: LiveSource(interface) implements the same iter_flows() using scapy/zeek.
Backend does not change.
"""
import json
from .base import FlowSource


class JsonlFlowSource(FlowSource):
    def __init__(self, path: str):
        self.path = path

    def iter_flows(self):
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
