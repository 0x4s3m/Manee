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

# --- Page Config ---
st.set_page_config(page_title="Husn (حصن) - Cyber Defense", layout="wide", initial_sidebar_state="expanded")

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
        "title": "Husn (حصن) - Intelligent Cyber Shield",
        "tagline": "National Defense Intelligent System",
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
        "normal": "Normal",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "run_scan": "Run Threat Scan",
        "simulate_btn": "Start Simulation",
        "explaining": "Generating SHAP Explanation..."
    },
    "ar": {
        "title": "حصن (Husn) - الدرع السيبراني الذكي",
        "tagline": "نظام ذكي للدفاع الوطني",
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
        "normal": "طبيعي",
        "high": "عالية",
        "medium": "متوسطة",
        "low": "منخفضة",
        "run_scan": "بدء فحص التهديدات",
        "simulate_btn": "بدء المحاكاة",
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
    st.title("Husn / حصن")
    st.button(T["lang_toggle"], on_click=toggle_lang)
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
st.markdown(f"<h1 style='text-align: center; color: #00FF00;'>{T['title']}</h1>", unsafe_content_html=True)
st.markdown(f"<h3 style='text-align: center;'>{T['tagline']}</h3>", unsafe_content_html=True)

# --- Components ---
if menu == T["real_time_monitor"]:
    st.subheader(T["real_time_monitor"])
    col1, col2 = st.columns(2)

    with col1:
        data = pd.DataFrame(np.random.randn(20, 3), columns=['Incoming', 'Outgoing', 'Dropped'])
        st.line_chart(data)

    with col2:
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = 15,
            title = {'text': "Network Load (%)"},
            gauge = {'axis': {'range': [None, 100]},
                     'bar': {'color': "green"}}))
        st.plotly_chart(fig)

elif menu == T["threat_detection"]:
    st.subheader(T["threat_detection"])
    if st.button(T["run_scan"]):
        with st.spinner("Analyzing traffic..."):
            time.sleep(1)
            # Sample traffic for prediction
            sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(5)
            X = sample_df[husn_ai.features]
            results = husn_ai.predict(X)

            res_df = pd.DataFrame(results)
            st.table(res_df)

elif menu == T["explainable_ai"]:
    st.subheader(T["explainable_ai"])
    st.write("Explaining the last detected threat using SHAP values.")

    sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(1)
    X = sample_df[husn_ai.features]

    with st.spinner(T["explaining"]):
        explainer, shap_values = husn_ai.explain(X)

        # Display SHAP Force Plot or Summary Plot
        st.write("Feature Importance for this Prediction:")
        fig, ax = plt.subplots()
        shap.summary_plot(shap_values, X, plot_type="bar", show=False)
        st.pyplot(fig)

elif menu == T["attack_simulation"]:
    st.subheader(T["attack_simulation"])
    target = st.text_input("Target IP", value="127.0.0.1")
    atk_type = st.selectbox("Select Attack", ["DDoS", "Port Scan", "Brute Force"])

    if st.button(T["simulate_btn"]):
        sim = AttackSimulator(target)
        with st.status("Simulating..."):
            if atk_type == "DDoS":
                sim.ddos_simulation(count=10)
            elif atk_type == "Port Scan":
                sim.port_scan_simulation()
            else:
                sim.brute_force_simulation()
        st.success(f"Simulation of {atk_type} completed!")

elif menu == T["system_status"]:
    st.subheader(T["system_status"])
    st.info(f"AI Engine: {T['status_online']}")
    st.success(f"Network Monitor: {T['status_active']}")
    st.success(f"SIEM Integration: {T['status_active']}")

elif menu == T["alerts_logs"]:
    st.subheader(T["alerts_logs"])
    logs = [
        {"Timestamp": "2026-04-24 10:05:01", "Event": "DDoS Detected", "Source": "192.168.1.100", "Severity": "High"},
        {"Timestamp": "2026-04-24 10:06:22", "Event": "Port Scan Started", "Source": "172.16.0.5", "Severity": "Medium"},
        {"Timestamp": "2026-04-24 10:10:05", "Event": "System Update", "Source": "Internal", "Severity": "Low"},
    ]
    st.dataframe(pd.DataFrame(logs), use_container_width=True)
