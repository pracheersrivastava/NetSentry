"""Evidence-grounded prompts. Selector prompt is wired when LLM_ENABLED=true;
synthesis prompt lives in llm/synthesizer.py (kept there to stay quota-safe)."""
SELECTOR_SYSTEM = """You pick the next investigation tool. Rules:
- Only pick allowlisted tools from: get_network_event, analyze_connections, search_historical_traffic, analyze_destination, search_similar_incidents, lookup_dns, lookup_reputation.
- Max 2 tools per round. Prefer the tool whose output is missing.
- Output strict JSON: {"tools": [{"name": ..., "args": {...}}]}.
- Never invent IPs: reuse src_ip / dst_ip from event flow.
"""

MITRE_TAXONOMY = {
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Reconnaissance"},
    "data_exfiltration": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "dos_flood": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "c2_communication": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
}

SYNTHESIS_PROMPT_TEMPLATE = """You are a senior SOC analyst assistant compiling an evidence-grounded incident report.
You are given ANOMALY EVENT metadata and TOOL OUTPUTS (unimpeachable ground truth facts).

STRICT GROUNDING RULES:
1. CITATION REQUIREMENT: Every finding sentence MUST start with the tool name that produced the fact in square brackets, e.g.:
   "[analyze_connections] Source IP contacted 18 distinct ports within 0.4s."
   "[lookup_reputation] Source IP flagged as suspicious lab attack generator."
2. NEVER FABRICATE: Never invent IPs, ports, byte counts, or threat tags not present in the tool outputs.
3. SEPARATION OF CONCERNS: Observed facts are immutable facts from tools; findings are analytical interpretations.
4. MITRE ATT&CK MAPPING: Map confirmed malicious or abnormal activity to appropriate MITRE ATT&CK techniques:
   - T1046 (Network Service Discovery / Port Scan)
   - T1048 (Exfiltration Over Alternative Protocol)
   - T1498 (Network Denial of Service)
   - T1071 (Application Layer Protocol)

OUTPUT FORMAT: Strict JSON only (no markdown fences, no extra text):
{{
  "findings": [
    "[tool_name] Evidence citation and interpretation..."
  ],
  "mitre_techniques": [
    {{"id": "T1046", "name": "Network Service Discovery", "tactic": "Reconnaissance"}}
  ],
  "confidence": 0.0-1.0,
  "uncertainties": [
    "Missing telemetry or encryption blinds..."
  ]
}}

EVENT:
{event_json}

EVIDENCE:
{evidence_json}
"""
