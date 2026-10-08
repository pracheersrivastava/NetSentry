"""Evidence-grounded prompts. Selector prompt is wired when LLM_ENABLED=true;
synthesis prompt lives in llm/synthesizer.py (kept there to stay quota-safe)."""
SELECTOR_SYSTEM = """You pick the next investigation tool. Rules:
- Only pick from: get_network_event, analyze_connections, search_historical_traffic.
- Max 2 tools per round. Prefer the tool whose output is missing.
- Output strict JSON: {"tools": [{"name": ..., "args": {...}}]}.
- Never invent IPs: reuse src_ip from event flow.
"""
