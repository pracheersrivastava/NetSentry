"""Quota-safe Gemini synthesis. Stub is always the fallback.

Rate-limit reality (user's keys):
- Pro / Antigravity-style: ~60 rpm / 100 rpd -> max ~100 LLM reports/day
- Flash-lite (3.1/3.5): ~15 rpm / 500 rpd -> better daily budget, slower per-minute

Design: backend already thresholds (only score>=0.85 creates open events),
so LLM is never called per-flow. On 429/quota/missing key -> return None and
caller keeps stub report. No retries that burn quota.
"""
import json
import os
import urllib.request


def enabled() -> bool:
    return os.getenv("LLM_ENABLED", "false").lower() == "true" and bool(os.getenv("GEMINI_API_KEY"))


def model_name() -> str:
    # accept MODEL= as alias (user .env used MODEL=), else GEMINI_MODEL, else default
    return os.getenv("GEMINI_MODEL") or os.getenv("MODEL") or "gemini-2.0-flash-lite"


def synthesize(event: dict, evidence: list[dict]) -> dict | None:
    """Try Gemini, return {findings, mitre_techniques, confidence, uncertainties} or None on any failure."""
    if not enabled():
        print("[llm] skipped: LLM_ENABLED!=true or GEMINI_API_KEY missing")
        return None
    key = os.getenv("GEMINI_API_KEY", "")
    model = model_name()

    from agent.prompts import SYNTHESIS_PROMPT_TEMPLATE

    prompt = SYNTHESIS_PROMPT_TEMPLATE.format(
        event_json=json.dumps(event)[:2500],
        evidence_json=json.dumps(evidence)[:7000],
    )
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.2, "maxOutputTokens": 800}}).encode()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    try:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read().decode())
        text = resp["candidates"][0]["content"]["parts"][0]["text"]
        # strip markdown fences if model adds them
        text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        out = json.loads(text)
        return {
            "findings": out.get("findings", []),
            "mitre_techniques": out.get("mitre_techniques", []),
            "confidence": float(out.get("confidence", 0.5)),
            "uncertainties": out.get("uncertainties", []),
        }
    except Exception as e:
        print(f"[llm] fallback to stub (reason: {type(e).__name__}: {e})")
        return None
