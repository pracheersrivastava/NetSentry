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
    st.subheader("Investigations + Incident Reports")
    invs = api("GET", "/investigations", params={"limit": 50}) or []
    if not invs:
        st.info("No investigations yet. Go to Anomalies -> Investigate.")
    else:
        sel = st.selectbox("Select investigation", [i["investigation_id"] for i in invs])
        selected_inv = next((i for i in invs if i["investigation_id"] == sel), {})
        
        rep = api("GET", f"/reports/{sel}")
        if rep:
            rj = rep.get("report_json", {})
            risk_obj = rj.get("risk_assessment", {})
            
            # --- Header metrics ---
            sev = str(rj.get("severity", "unknown")).upper()
            score = rj.get("anomaly_score", 0.0)
            conf = rj.get("confidence", 0.0)
            status = rep.get("reviewer_status", "pending").upper()
            
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Severity", sev)
            m2.metric("Anomaly Score", f"{score:.2f}")
            m3.metric("Confidence", f"{conf * 100:.0f}%")
            m4.metric("Disposition", status)

            # --- Risk Rationale banner ---
            rationale = risk_obj.get("rationale")
            if rationale:
                st.info(f"**Risk Assessment Rationale:** {rationale}")

            # --- MITRE ATT&CK Mapping ---
            mitre_list = rj.get("mitre_techniques", [])
            if mitre_list:
                st.markdown("##### MITRE ATT&CK Techniques Identified")
                mitre_cols = st.columns(min(len(mitre_list), 4))
                for idx, m in enumerate(mitre_list):
                    col = mitre_cols[idx % len(mitre_cols)]
                    col.markdown(f"<div class='card' style='padding:10px;'><b>{m.get('id')}: {m.get('name')}</b><br><span class='small'>Tactic: {m.get('tactic')}</span></div>", unsafe_allow_html=True)

            # --- Hypotheses Evaluation Matrix ---
            hyps = rj.get("hypotheses", [])
            if hyps:
                st.markdown("##### Investigative Hypotheses Evaluation")
                for h in hyps:
                    h_stat = str(h.get("status", "inconclusive")).upper()
                    h_conf = h.get("confidence", 0.0)
                    summary = h.get("evidence_summary", "")
                    h_name = str(h.get("hypothesis", "")).replace("_", " ").title()
                    
                    if h_stat == "CONFIRMED":
                        st.success(f"**[CONFIRMED] {h_name}** (Confidence: {h_conf*100:.0f}%)\n\n{summary}")
                    elif h_stat == "REFUTED":
                        st.info(f"**[REFUTED] {h_name}** (Confidence: {h_conf*100:.0f}%)\n\n{summary}")
                    else:
                        st.warning(f"**[INCONCLUSIVE] {h_name}**\n\n{summary}")

            # --- Risk Factors Breakdown ---
            factors = risk_obj.get("factor_breakdown", [])
            if factors:
                with st.expander("Explainable Risk Factor Breakdown", expanded=False):
                    f_rows = []
                    for f in factors:
                        f_rows.append({
                            "Signal": f.get("signal", "").replace("_", " ").title(),
                            "Flagged": "YES" if f.get("flagged") else "no",
                            "Contribution": f"+{f.get('contribution', 0):.2f}",
                            "Weight": f"{f.get('weight', 0):.2f}",
                            "Observed Value": str(f.get("observed_value", "")),
                            "Description": f.get("description", ""),
                        })
                    st.dataframe(pd.DataFrame(f_rows), use_container_width=True)

            # --- Observed Facts vs Grounded Findings ---
            st.markdown("##### Investigation Evidence Synthesis")
            col_left, col_right = st.columns(2)
            with col_left:
                st.markdown("**Observed Telemetry Facts (Immutable):**")
                for fact in rj.get("observed_facts", []):
                    st.markdown(f"- {fact}")
            with col_right:
                st.markdown("**Grounded Security Findings:**")
                for finding in rj.get("findings", []):
                    st.markdown(f"- {finding}")

            # --- Next Steps & Uncertainties ---
            with st.expander("Recommended Next Steps & Telemetry Bounds"):
                st.markdown("**Next Investigative Steps:**")
                for step in rj.get("recommended_next_steps", []):
                    st.markdown(f"1. {step}")
                st.markdown("**Known Telemetry Uncertainties:**")
                for unc in rj.get("uncertainties", []):
                    st.markdown(f"- {unc}")

            with st.expander("Full Report JSON Artifact"):
                st.json(rj)

            # --- Analyst Actions ---
            col1, col2 = st.columns(2)
            if col1.button("Approve Incident"):
                api("POST", f"/reports/{rep['report_id']}/review", params={"status": "approved"})
                st.success("Report approved by analyst.")
                st.rerun()
            if col2.button("Reject as False Positive"):
                api("POST", f"/reports/{rep['report_id']}/review", params={"status": "rejected"})
                st.warning("Report marked as rejected.")
                st.rerun()

        # --- Tool Evidence Audit ---
        ev = api("GET", f"/investigations/{sel}/evidence") or []
        st.markdown(f"<div class='card'><h4>Evidence Audit Log ({len(ev)} Items)</h4><div class='small'>{' | '.join(e['source_tool'] for e in ev)}</div></div>", unsafe_allow_html=True)
        for e in ev:
            with st.expander(f"{e['source_tool']} ({e['evidence_type']})"):
                st.json(e["payload"])
