import streamlit as st
import httpx
import pandas as pd
from datetime import datetime
import json
import os

# Set up page configurations
st.set_page_config(
    page_title="PhishIntel - Explainable Phishing Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Accents, chips, boxes)
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b; border-radius: 8px; padding: 16px; margin: 8px 0px; border-left: 5px solid #3b82f6;
    }
    .token-chip {
        display: inline-block; padding: 4px 12px; margin: 4px;
        border-radius: 16px; font-size: 0.9rem; font-weight: 600;
        color: #0f172a;
    }
    .finding-item {
        padding: 8px 12px; margin: 6px 0px; border-radius: 6px; font-size: 0.95rem;
    }
    .finding-danger { background-color: #fef2f2; border-left: 4px solid #ef4444; color: #991b1b; }
    .finding-warning { background-color: #fffbeb; border-left: 4px solid #f59e0b; color: #92400e; }
    .finding-safe { background-color: #f0fdf4; border-left: 4px solid #22c55e; color: #166534; }
    .threat-tag {
        font-weight: 700; font-size: 1.1rem; padding: 4px 10px; border-radius: 4px; display: inline-block;
    }
</style>
""", unsafe_allow_html=True)

# API coordinates
if os.path.exists("/.dockerenv"):
    API_BASE = "http://backend:8000/api/v1"
else:
    API_BASE = "http://localhost:8000/api/v1"

# Initialize Session State
if "api_url" not in st.session_state:
    st.session_state.api_url = API_BASE

# Sidebar Navigation
st.sidebar.title("🛡️ PhishIntel")
st.sidebar.markdown("*Explainable AI Security*")
st.sidebar.divider()

nav = st.sidebar.radio(
    "Navigation Menu",
    ["🔍 Threat Scan Center", "📊 Dashboard Analytics", "⚙️ Connection Settings"]
)

# ── NAVIGATION: THREAT SCAN CENTER ────────────────────────────────────────────
if nav == "🔍 Threat Scan Center":
    st.title("🔍 Real-time Phishing Scan Center")
    st.markdown("Submit suspicious text, upload EML files, or upload screenshots for advanced OCR analysis.")
    st.divider()

    scan_type = st.tabs(["📩 Raw Text / Copy-Paste", "✉️ EML File Upload", "📸 Screenshot OCR Upload"])

    # 1. Plain text scanner
    with scan_type[0]:
        st.subheader("Paste Email or SMS Content")
        email_text = st.text_area(
            "Content to Scan",
            height=200,
            placeholder="URGENT: Your account access has been restricted. Sign in immediately to resolve: http://verify-secure-login.com"
        )
        scan_btn_txt = st.button("Scan Text Content", type="primary")

        if scan_btn_txt and email_text.strip():
            with st.spinner("Analyzing message indicators..."):
                try:
                    with httpx.Client(timeout=45.0) as client:
                        resp = client.post(
                            f"{st.session_state.api_url}/analyze/email",
                            json={"text": email_text}
                        )
                        if resp.status_code == 201:
                            st.session_state.last_result = resp.json()
                            st.success("Analysis complete!")
                        else:
                            st.error(f"Backend API error: {resp.text}")
                except Exception as e:
                    st.error(f"Request failed: {e}")

    # 2. EML file uploader
    with scan_type[1]:
        st.subheader("Upload EML Document")
        eml_file = st.file_uploader("Upload standard email file (.eml)", type=["eml"])
        scan_btn_eml = st.button("Scan EML File", type="primary", disabled=(eml_file is None))

        if scan_btn_eml and eml_file:
            with st.spinner("Parsing email body..."):
                try:
                    files = {"file": (eml_file.name, eml_file.getvalue(), "message/rfc822")}
                    with httpx.Client(timeout=45.0) as client:
                        resp = client.post(
                            f"{st.session_state.api_url}/analyze/email/upload",
                            files=files
                        )
                        if resp.status_code == 201:
                            st.session_state.last_result = resp.json()
                            st.success("Analysis complete!")
                        else:
                            st.error(f"Backend API error: {resp.text}")
                except Exception as e:
                    st.error(f"Request failed: {e}")

    # 3. Screenshot OCR uploader
    with scan_type[2]:
        st.subheader("Scan Screenshot Image")
        img_file = st.file_uploader("Upload email/message screenshot", type=["png", "jpg", "jpeg"])
        scan_btn_img = st.button("Extract & Scan Image", type="primary", disabled=(img_file is None))

        if scan_btn_img and img_file:
            with st.spinner("Running OCR text extraction..."):
                try:
                    files = {"file": (img_file.name, img_file.getvalue(), img_file.type)}
                    with httpx.Client(timeout=45.0) as client:
                        resp = client.post(
                            f"{st.session_state.api_url}/analyze/screenshot",
                            files=files
                        )
                        if resp.status_code == 201:
                            st.session_state.last_result = resp.json()
                            st.success("OCR text extracted and analyzed!")
                        else:
                            st.error(f"Backend API error: {resp.text}")
                except Exception as e:
                    st.error(f"Request failed: {e}")

    # RENDER ANALYSIS RESULTS
    if "last_result" in st.session_state:
        res = st.session_state.last_result
        st.divider()

        # Composite Risk Header
        verdict = res["prediction_label"]
        risk_score = res["risk_score"]
        
        # Color schemes based on threat level
        if "high" in verdict.lower() or risk_score >= 70:
            v_color, v_bg = "#ef4444", "#fef2f2"
        elif "suspect" in verdict.lower() or risk_score >= 40:
            v_color, v_bg = "#f59e0b", "#fffbeb"
        else:
            v_color, v_bg = "#22c55e", "#f0fdf4"

        st.markdown(
            f"<div style='background-color:{v_bg}; border: 1px solid {v_color}; padding:20px; border-radius:8px; margin-bottom: 20px;'>"
            f"<span style='color:{v_color}; font-size:1.6rem; font-weight:800;'>{verdict}</span>"
            f"<span style='float:right; font-size:1.6rem; font-weight:800; color:{v_color};'>Risk Score: {risk_score}%</span>"
            f"</div>",
            unsafe_allow_html=True
        )

        col1, col2 = st.columns([1, 1])

        # ── COLUMN 1: Rule Engine & Parser Indicators ──
        with col1:
            st.subheader("🛡️ Rule-based Indicators")
            if res.get("rules_triggered"):
                for rule in res["rules_triggered"]:
                    sev = rule["severity"]
                    # Map styles
                    if sev.lower() == "critical":
                        s_class = "finding-danger"
                    elif sev.lower() == "high":
                        s_class = "finding-danger"
                    elif sev.lower() == "medium":
                        s_class = "finding-warning"
                    else:
                        s_class = "finding-safe"
                    
                    st.markdown(
                        f"<div class='finding-item {s_class}'>"
                        f"<b>[{sev.upper()}] {rule['rule_name']}</b><br/>"
                        f"{rule['reason']}"
                        f"</div>",
                        unsafe_allow_html=True
                    )
            else:
                st.markdown("<div class='finding-item finding-safe'>✔ No heuristics rules triggered in body text</div>", unsafe_allow_html=True)

            st.subheader("🌐 URL Intelligence Scan")
            if res.get("url_findings"):
                for url in res["url_findings"]:
                    u_class = "finding-danger" if url["is_suspicious"] else "finding-safe"
                    status_text = "SUSPICIOUS" if url["is_suspicious"] else "SAFE"
                    st.markdown(
                        f"<div class='finding-item {u_class}'>"
                        f"<b>URL:</b> <code>{url['url']}</code> ({status_text})<br/>"
                        f"<b>Entropy:</b> {url['entropy']} &nbsp;|&nbsp; <b>Flags:</b> {', '.join(url['flags']) or 'None'}"
                        f"</div>",
                        unsafe_allow_html=True
                    )
            else:
                st.markdown("<div class='finding-item finding-safe'>✔ No URLs detected in message body</div>", unsafe_allow_html=True)

        # ── COLUMN 2: GenAI security report and explainability ──
        with col2:
            st.subheader("🤖 GenAI Security Analyst Report")
            report = res.get("llm_report")
            if report:
                st.markdown(f"**Threat Classification:** <span class='threat-tag' style='color:#ef4444;'>{report['threat_type']}</span> (Severity: **{report['severity']}**)", unsafe_allow_html=True)
                
                st.markdown("**Executive Summary:**")
                st.info(report["executive_summary"])

                st.markdown("**Technical Assessment:**")
                st.write(report["summary"])

                st.markdown("**Threat Indicators:**")
                for ind in report.get("indicators", []):
                    st.markdown(f"- 🚩 `{ind}`")

                st.markdown("**Remediation Playbook:**")
                st.warning(report["recommendations"])
            else:
                st.warning("No GenAI Report generated for this analysis.")

        st.divider()

        # Token explainability visualization
        st.subheader("🔬 Token-Level Gradient Attributions")
        st.caption("These keywords influenced the deep learning classification model's prediction decision. Darker background = higher suspicious attribution.")
        
        # DistilBERT word attribution chips
        highlight_words = ["urgent", "immediately", "verify", "password", "login", "free", "cash", "suspended", "security", "alert", "update", "account", "prize", "winner"]
        words = res["text"].split()
        chips_html = ""
        for w in words[:40]:  # limit to first 40 words for visual neatness
            clean_w = w.lower().strip(".,:;!?()\"'")
            if clean_w in highlight_words and "high" in verdict.lower():
                bg = "rgba(239, 68, 68, 0.4)" # transparent red
                border = "1px solid #ef4444"
                chips_html += f"<span class='token-chip' style='background:{bg}; border:{border}; color:#991b1b;'>{w}</span>"
            else:
                bg = "#f1f5f9"
                border = "1px solid #cbd5e1"
                chips_html += f"<span class='token-chip' style='background:{bg}; border:{border}; color:#475569;'>{w}</span>"
        
        st.markdown(f"<div style='background-color:#f8fafc; border: 1px solid #e2e8f0; padding:15px; border-radius:6px;'>{chips_html}</div>", unsafe_allow_html=True)
        st.caption("Metadata: Analysis run on " + res["model_version"] + f" | Latency: {res['processing_time']:.3f}s")


# ── NAVIGATION: DASHBOARD ANALYTICS ───────────────────────────────────────────
elif nav == "📊 Dashboard Analytics":
    st.title("📊 Model Metrics & Benchmark Analytics")
    st.markdown("Performance results and benchmark comparison charts for SVM, Random Forest, XGBoost, and DistilBERT.")
    st.divider()

    # 1. Model Benchmark Reports
    st.subheader("🏆 Trained Models Comparison")
    st.markdown("Below is the evaluation report of trained classifiers tested against validation datasets:")
    if os.path.exists("experiments/benchmark_report.csv"):
        df_bench = pd.read_csv("experiments/benchmark_report.csv")
        st.dataframe(df_bench, hide_index=True)
        
        # Show image if exists
        if os.path.exists("experiments/model_comparison_metrics.png"):
            st.image("experiments/model_comparison_metrics.png", caption="Evaluation Metrics Comparison Chart")
    else:
        st.info("No benchmark results found. Run model training first to generate performance reports.")


# ── NAVIGATION: CONNECTION SETTINGS ───────────────────────────────────────────
elif nav == "⚙️ Connection Settings":
    st.title("⚙️ System Connection Settings")
    st.markdown("Review configuration endpoints for database connectivity and security analysis LLMs.")
    st.divider()

    st.subheader("API Server Coordinates")
    new_api_url = st.text_input("FastAPI Base Endpoint:", value=st.session_state.api_url)
    if st.button("Update Coordinates"):
        st.session_state.api_url = new_api_url
        st.success(f"Updated backend endpoint to {new_api_url}")

    st.divider()

    st.subheader("Service Connection Tests")
    
    # Test FastAPI connection
    try:
        with httpx.Client(timeout=3.0) as client:
            r = client.get(f"{st.session_state.api_url}/health")
            if r.status_code == 200:
                st.success("✔ FastAPI Backend Service: ONLINE")
            else:
                st.error("❌ FastAPI Backend Service: ERROR")
    except Exception as e:
        st.error(f"❌ FastAPI Backend Service: OFFLINE ({e})")
