import os
import json
import requests
import streamlit as st

API_BASE = os.getenv("FRAUDSHIELD_API", "http://127.0.0.1:8000")

st.set_page_config(page_title="FraudShield AI", layout="wide")

st.title("FraudShield AI")
st.caption("Generative AI-Powered Automated Malware Investigation for Fraudulent Android APKs")

# Sidebar: API key and navigation
api_key = st.sidebar.text_input("API Key (optional)", type="password", value=os.getenv("FRAUDSHIELD_API_KEY", ""))
headers = {"X-API-Key": api_key} if api_key else {}
page = st.sidebar.radio("Navigation", ["Upload & Analyze", "Investigation Report", "Security Copilot"])

if page == "Upload & Analyze":
    st.header("Upload APK")
    uploaded = st.file_uploader("Choose an APK file", type=["apk"])
    if uploaded and st.button("Run Investigation"):
        with st.spinner("Uploading..."):
            files = {"file": (uploaded.name, uploaded.getvalue(), "application/vnd.android.package-archive")}
            upload_resp = requests.post(f"{API_BASE}/api/upload", files=files, headers=headers)
            if upload_resp.status_code != 200:
                st.error(f"Upload failed: {upload_resp.text}")
                st.stop()
            file_id = upload_resp.json()["file_id"]
            st.session_state["file_id"] = file_id
            st.session_state["apk_name"] = uploaded.name

        with st.spinner("Investigating (this may take a minute)..."):
            inv_resp = requests.post(f"{API_BASE}/api/investigate", data={"file_id": file_id}, headers=headers)
            if inv_resp.status_code != 200:
                st.error(f"Investigation failed: {inv_resp.text}")
                st.stop()
            investigation = inv_resp.json()
            st.session_state["investigation"] = investigation
            st.success("Investigation complete!")

    if "investigation" in st.session_state:
        inv = st.session_state["investigation"]
        risk = inv.get("risk_score", {})
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", f"{risk.get('score', 0)}/100", risk.get("category", "Unknown"))
        col2.metric("Category", inv.get("classification", {}).get("class", "Unknown"))
        col3.metric("Confidence", inv.get("classification", {}).get("confidence", 0))
        st.json({k: v for k, v in inv.items() if k != "static_analysis"})

elif page == "Investigation Report":
    st.header("Investigation Report")
    if "investigation" not in st.session_state:
        st.warning("Please upload and analyze an APK first.")
    else:
        inv = st.session_state["investigation"]
        reports = inv.get("reports", {})
        apk_id = inv["metadata"]["sha256"]
        st.write(f"Package: `{inv['metadata'].get('package_name', 'N/A')}`")
        st.write(f"SHA256: `{apk_id}`")

        c1, c2, c3, c4 = st.columns(4)
        if c1.button("Download JSON"):
            st.markdown(f"[Open JSON]({API_BASE}/api/reports/json?apk_id={apk_id})")
        if c2.button("Download PDF"):
            st.markdown(f"[Open PDF]({API_BASE}/api/reports/pdf?apk_id={apk_id})")
        if c3.button("Open HTML"):
            st.markdown(f"[Open HTML]({API_BASE}/api/reports/html?apk_id={apk_id})")
        if c4.button("Attack Chain"):
            st.markdown(f"[Open Mermaid]({API_BASE}/api/reports/mermaid?apk_id={apk_id})")

        # Show VirusTotal enrichment if available
        vt = inv.get("virus_total", {})
        if vt.get("enabled") and vt.get("results"):
            st.subheader("VirusTotal Enrichment")
            st.dataframe(vt["results"])

        st.subheader("Executive Summary")
        st.write(inv.get("ai_summary", {}).get("banking_impact", "No summary available."))
        st.subheader("Fraud Impact")
        st.json(inv.get("fraud_impact", {}))
        st.subheader("Dynamic / Behavioral Findings")
        dynamic = inv.get("dynamic_analysis", {})
        st.write(f"Sandbox: `{dynamic.get('sandbox', 'unknown')}`")
        if dynamic.get("is_simulated"):
            st.warning("No live emulator/MobSF/ADB available. These findings are simulated from static indicators.")
        st.write(f"Reason: `{dynamic.get('reason', '')}`")
        st.dataframe(dynamic.get("findings", []))
        st.subheader("MITRE Mapping")
        st.dataframe(inv.get("mitre_mapping", []))
        st.subheader("IOCs")
        st.json(inv.get("iocs", {}))

elif page == "Security Copilot":
    st.header("Security Copilot")
    if "investigation" not in st.session_state:
        st.warning("Please upload and analyze an APK first.")
    else:
        apk_id = st.session_state["investigation"]["metadata"]["sha256"]
        question = st.text_input("Ask about the APK investigation")
        if st.button("Ask") and question:
            with st.spinner("Copilot is thinking..."):
                resp = requests.post(f"{API_BASE}/api/chat", json={"apk_id": apk_id, "question": question}, headers=headers)
                if resp.status_code == 200:
                    answer = resp.json().get("answer", "No answer.")
                    st.write(answer)
                    with st.expander("Retrieved context"):
                        st.json(resp.json().get("context", []))
                else:
                    st.error(f"Chat failed: {resp.text}")

        st.caption("Example questions: Why is this malicious? | Can it steal OTPs? | Show suspicious domains. | Explain risk score.")
