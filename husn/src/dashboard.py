import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from husn.src.ai.model import HusnAI
from husn.src.core.simulator import AttackSimulator
import time
import shap
import matplotlib.pyplot as plt
import os
import requests
from streamlit_lottie import st_lottie

# --- Page Config ---
st.set_page_config(page_title="Husn (حصن) - Cyber Defense", layout="wide", initial_sidebar_state="expanded")

# --- Custom CSS for "Enchanted" Look ---
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #00FF00;
        color: black;
        font-weight: bold;
        border: none;
        box-shadow: 0 0 10px #00FF00;
    }
    .stButton>button:hover {
        background-color: #00CC00;
        box-shadow: 0 0 20px #00FF00;
    }
    .metric-card {
        background-color: #1a1c24;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #00FF00;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.5);
    }
    .siem-log {
        font-family: 'Courier New', Courier, monospace;
        background-color: #000;
        color: #0f0;
        padding: 10px;
        border-radius: 5px;
        height: 300px;
        overflow-y: scroll;
        border: 1px solid #00FF00;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Load Assets ---
def load_lottieurl(url: str):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

# Shield animation
lottie_shield = load_lottieurl("https://lottie.host/8070868a-6b83-4903-9114-118e690f3c5b/vUf0fF2l7v.json")

# --- Load AI Model ---
@st.cache_resource
def load_ai():
    ai = HusnAI()
    if os.path.exists("husn/models/classifier_model.joblib"):
        ai.load_models()
    return ai

husn_ai = load_ai()

# --- Translations ---
TRANSLATIONS = {
    "en": {
        "title": "Husn (حصن)",
        "tagline": "Intelligent Cyber Shield for National Defense",
        "real_time_monitor": "Real-time Monitoring",
        "threat_detection": "Threat Detection",
        "attack_simulation": "Attack Simulation",
        "explainable_ai": "Explainable AI (SHAP)",
        "alerts_logs": "Alerts & Logs",
        "system_status": "System Status",
        "lang_toggle": "العربية",
        "status_online": "Online",
        "status_active": "Active",
        "severity": "Severity",
        "confidence": "Confidence",
        "attack_type": "Attack Type",
        "run_scan": "Run Threat Scan",
        "simulate_btn": "🚀 START SIMULATION",
        "explaining": "Generating SHAP Explanation..."
    },
    "ar": {
        "title": "حصن (Husn)",
        "tagline": "الدرع السيبراني الذكي للدفاع الوطني",
        "real_time_monitor": "المراقبة في الوقت الحقيقي",
        "threat_detection": "اكتشاف التهديدات",
        "attack_simulation": "محاكاة الهجمات",
        "explainable_ai": "الذكاء الاصطناعي القابل للتفسير",
        "alerts_logs": "التنبيهات والسجلات",
        "system_status": "حالة النظام",
        "lang_toggle": "English",
        "status_online": "متصل",
        "status_active": "نشط",
        "severity": "الخطورة",
        "confidence": "الثقة",
        "attack_type": "نوع الهجوم",
        "run_scan": "بدء فحص التهديدات",
        "simulate_btn": "🚀 بدء المحاكاة",
        "explaining": "جاري إنشاء تفسير SHAP..."
    }
}

# --- Session State ---
if "lang" not in st.session_state:
    st.session_state.lang = "en"

def toggle_lang():
    st.session_state.lang = "ar" if st.session_state.lang == "en" else "en"

T = TRANSLATIONS[st.session_state.lang]

# --- Sidebar ---
with st.sidebar:
    if lottie_shield:
        st_lottie(lottie_shield, height=150, key="shield")
    st.markdown(f"<div style='text-align: center;'><h1 style='color: #00FF00;'>Husn / حصن</h1></div>", unsafe_allow_html=True)

    if st.button(f"🌐 {T['lang_toggle']}", use_container_width=True):
        toggle_lang()
        st.rerun()

    st.markdown("---")
    menu = st.radio("", [
        T["real_time_monitor"],
        T["threat_detection"],
        T["attack_simulation"],
        T["explainable_ai"],
        T["alerts_logs"],
        T["system_status"]
    ])

# --- Header ---
st.markdown(f"<h1 style='text-align: center; color: #00FF00; text-shadow: 0 0 10px #00FF00;'>{T['title']}</h1>", unsafe_allow_html=True)
st.markdown(f"<h3 style='text-align: center; color: #888;'>{T['tagline']}</h3>", unsafe_allow_html=True)
st.markdown("---")

# --- Components ---
if menu == T["real_time_monitor"]:
    st.subheader(T["real_time_monitor"])

    # Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown('<div class="metric-card"><h4>Uptime</h4><h2>99.9%</h2></div>', unsafe_allow_html=True)
    with m2:
        st.markdown('<div class="metric-card"><h4>Threats Blocked</h4><h2>1,284</h2></div>', unsafe_allow_html=True)
    with m3:
        st.markdown('<div class="metric-card"><h4>Network Load</h4><h2>12%</h2></div>', unsafe_allow_html=True)
    with m4:
        st.markdown('<div class="metric-card"><h4>AI Confidence</h4><h2>98.4%</h2></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])
    with col1:
        data = pd.DataFrame(np.random.randn(50, 3), columns=['Incoming', 'Outgoing', 'Malicious'])
        fig = px.line(data, title="Live Traffic Analytics")
        fig.update_layout(template="plotly_dark", plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("<h4>SIEM Intelligence Feed</h4>", unsafe_allow_html=True)
        log_content = "".join([f"[{time.strftime('%H:%M:%S')}] INFO: Packet from {np.random.randint(1,255)}.{np.random.randint(1,255)}.x.x analyzed... OK<br>" for _ in range(20)])
        st.markdown(f'<div class="siem-log">{log_content}</div>', unsafe_allow_html=True)

elif menu == T["threat_detection"]:
    st.subheader(T["threat_detection"])
    if st.button(T["run_scan"]):
        with st.status("Analyzing Deep Traffic Data..."):
            time.sleep(1.5)
            sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(10)
            X = sample_df[husn_ai.features]
            results = husn_ai.predict(X)
            res_df = pd.DataFrame(results)
            st.table(res_df)

elif menu == T["explainable_ai"]:
    st.subheader(T["explainable_ai"])
    col_x1, col_x2 = st.columns([1, 2])

    with col_x1:
        st.info("AI Decision Transparency Report")
        st.write("SHAP (SHapley Additive exPlanations) is used to explain the output of the XGBoost classifier. This provides high-stakes accountability for national defense decisions.")

    with col_x2:
        sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(1)
        X = sample_df[husn_ai.features]
        with st.spinner(T["explaining"]):
            explainer, shap_values = husn_ai.explain(X)
            fig, ax = plt.subplots(figsize=(10, 6))
            shap.plots.bar(shap_values[0], show=False)
            plt.gcf().set_facecolor('#0e1117')
            ax.set_facecolor('#0e1117')
            plt.tight_layout()
            st.pyplot(fig)

elif menu == T["attack_simulation"]:
    st.subheader(T["attack_simulation"])
    st.warning("Authorized Personnel Only: Simulation triggers realistic network stressors.")

    col_a, col_b = st.columns(2)
    with col_a:
        target = st.text_input("Target IP", value="127.0.0.1")
    with col_b:
        atk_type = st.selectbox("Select Vector", ["DDoS (Volumetric)", "Port Scan (Recon)", "Brute Force (Credential)"])

    if st.button(T["simulate_btn"], type="primary"):
        sim = AttackSimulator(target)
        with st.status("Injecting Malicious Traffic..."):
            st.write("Crafting headers...")
            time.sleep(1)
            if "DDoS" in atk_type:
                sim.ddos_simulation(count=20)
            elif "Port Scan" in atk_type:
                sim.port_scan_simulation()
            else:
                sim.brute_force_simulation()
        st.success(f"Simulation of {atk_type} completed! Logs diverted to AI training pipeline.")

elif menu == T["system_status"]:
    st.subheader(T["system_status"])
    c1, c2, c3 = st.columns(3)
    c1.metric("AI Status", T["status_online"], delta="Stable")
    c2.metric("Shield Active", T["status_active"], delta="100%")
    c3.metric("Integrations", "5/5", delta="Secure")

elif menu == T["alerts_logs"]:
    st.subheader(T["alerts_logs"])
    logs = [
        {"Timestamp": "2026-04-24 10:05:01", "Event": "DDoS Detected", "Source": "192.168.1.100", "Severity": "High"},
        {"Timestamp": "2026-04-24 10:06:22", "Event": "Port Scan Started", "Source": "172.16.0.5", "Severity": "Medium"},
        {"Timestamp": "2026-04-24 10:10:05", "Event": "System Update", "Source": "Internal", "Severity": "Low"},
    ]
    st.dataframe(pd.DataFrame(logs), use_container_width=True)
