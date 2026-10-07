"""NetSentry SOC dashboard — thin UI over frozen backend APIs. No ML imports here.

Run: streamlit run dashboard/app.py
Backend must be up: uvicorn api.main:app --port 8000
"""
import os

import httpx
import pandas as pd
import streamlit as st

API = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(page_title="NetSentry SOC", layout="wide", page_icon="S")
st.markdown(
    """<style>
body { font-family: Inter, sans-serif; }
.card { background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 12px; color: #e2e8f0; }
.card h4 { margin: 0 0 8px 0; }
.small { color: #94a3b8; font-size: 12px; }
.stButton>button { border-radius: 8px; }
</style>""",
    unsafe_allow_html=True,
)


def api(method: str, path: str, **kw):
    try:
        r = httpx.request(method, f"{API}{path}", timeout=15, **kw)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API {method} {path} failed: {e}")
        return None


st.sidebar.title("NetSentry SOC")
page = st.sidebar.radio("View", ["Live", "Anomalies", "Investigations"])
st.sidebar.caption(f"Backend: {API}")

health = api("GET", "/health") or {}
model = api("GET", "/model/info") or {}
c1, c2, c3, c4 = st.columns(4)
c1.metric("Backend", health.get("status", "?"))
c2.metric("Model", health.get("model", "?"))
c3.metric("LLM", f"{health.get('llm_model', '-')} ({'on' if health.get('llm_enabled') else 'off'})")
c4.metric("Features", len(model.get("feature_order", [])) or "?")

if page == "Live":
    st.subheader("Recent flows")
    if st.button("Refresh"):
        st.rerun()
    flows = api("GET", "/flows", params={"limit": 50}) or []
    if flows:
        df = pd.DataFrame([{"flow": f["flow_id"], "src": f["src_ip"], "dst": f["dst_ip"], "port": f["dst_port"], "proto": f["protocol"]} for f in flows])
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No flows yet. Run: python scripts/demo_replay.py")

elif page == "Anomalies":
    st.subheader("Anomaly events")
    status = st.selectbox("Status", ["", "open", "monitoring", "closed"], index=0)
    params: dict = {"limit": 100}
    if status:
        params["status"] = status
    anomalies = api("GET", "/anomalies", params=params) or []
    if not anomalies:
        st.info("No anomalies. Ingest burst flow first.")
    else:
        df = pd.DataFrame([{"event": a["event_id"], "flow": a["flow_id"], "score": a["anomaly_score"], "model": a["model_version"], "status": a["status"]} for a in anomalies])
        st.dataframe(df, use_container_width=True)
        sel = st.selectbox("Select event", [a["event_id"] for a in anomalies])
        col1, col2 = st.columns(2)
        if col1.button("Investigate"):
            inv = api("POST", f"/investigations/{sel}")
            if inv:
                st.success(f"Investigation {inv['investigation_id']} ({inv['state']})")
        if col2.button("Close event"):
            upd = api("PATCH", f"/anomalies/{sel}", params={"status": "closed"})
            if upd:
                st.success(f"{sel} closed")
                st.rerun()

else:
    st.subheader("Investigations + reports")
    invs = api("GET", "/investigations", params={"limit": 50}) or []
    if not invs:
        st.info("No investigations yet. Go to Anomalies -> Investigate.")
    else:
        sel = st.selectbox("Select investigation", [i["investigation_id"] for i in invs])
        ev = api("GET", f"/investigations/{sel}/evidence") or []
        st.markdown(f"<div class='card'><h4>Evidence ({len(ev)})</h4><div class='small'>{' | '.join(e['source_tool'] for e in ev)}</div></div>", unsafe_allow_html=True)
        for e in ev:
            with st.expander(f"{e['source_tool']} ({e['evidence_type']})"):
                st.json(e["payload"])
        rep = api("GET", f"/reports/{sel}")
        if rep:
            st.markdown("<div class='card'><h4>Incident report</h4></div>", unsafe_allow_html=True)
            rj = rep["report_json"]
            st.write(f"Severity: {rj.get('severity')} | Score: {rj.get('anomaly_score')} | Confidence: {rj.get('confidence')}")
            st.write("Findings:")
            for f in rj.get("findings", []):
                st.write(f"- {f}")
            with st.expander("Full report JSON"):
                st.json(rj)
            col1, col2 = st.columns(2)
            if col1.button("Approve"):
                api("POST", f"/reports/{rep['report_id']}/review", params={"status": "approved"})
                st.success("approved")
            if col2.button("Reject"):
                api("POST", f"/reports/{rep['report_id']}/review", params={"status": "rejected"})
                st.success("rejected")
