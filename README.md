# Husn (حصن) - Intelligent Cyber Shield

<div align="center">
  <img src="https://raw.githubusercontent.com/username/repo/main/assets/husn_logo.png" alt="Husn Logo" width="200"/>
  <h3>Intelligent Cyber Defense System for National Security</h3>
</div>

Husn (حصن) is a state-of-the-art AI-powered cybersecurity system designed for the DefensThon 2026 competition. It features a professional React-based dashboard and a Metasploit-style CLI for comprehensive network protection.

---

## ✨ Key Features

- **🚀 High-Professional Dashboard**: Built with **React + TypeScript + Tailwind CSS**, featuring neon-cyber aesthetics and smooth Framer Motion animations.
- **🛡️ Dual Interface**: Fully integrated FastAPI backend supporting both a modern web UI and an interactive terminal CLI.
- **🧠 Hybrid AI Engine**: Advanced threat detection using **IsolationForest** and **XGBoost** trained on network flow signatures.
- **🔍 Explainable AI (SHAP)**: Visual feature importance plots to explain why the AI flagged specific traffic as malicious.
- **⚡ Active Defense**: Automated IP blocking and session mitigation for high-severity threats.
- **🌍 Bilingual Support**: Seamless English and Arabic toggle for the entire web interface.
- **📡 Realistic Simulation**: Scapy-powered attack generation for training and demonstration.

---

## 📁 Project Structure
```
husn/
├── backend/            # FastAPI, AI Models, & CLI
│   ├── husn/           # Core library
│   ├── main.py         # API entry point
│   └── data/           # Datasets
├── frontend/           # React + TypeScript + Vite
└── run.py              # Root orchestrator
```

## 🚀 Installation

1. **Backend Setup**:
   ```bash
   pip install -r backend/requirements.txt
   ```

2. **Frontend Setup**:
   ```bash
   cd frontend && npm install && cd ..
   ```

## 🛠️ Usage

Launch the full system using the root orchestrator:

- **Dual Mode (Dashboard + CLI)**:
  ```bash
  python run.py both
  ```

- **Individual Services**:
  - `python run.py backend`
  - `python run.py frontend`
  - `python run.py cli`

---

# حصن (Husn) - الدرع السيبراني الذكي

حصن هو نظام للأمن السيبراني مدعوم بالذكاء الاصطناعي تم تطويره لمسابقة DefensThon 2026. يتميز النظام بلوحة معلومات احترافية مبنية على React وواجهة سطر أوامر بأسلوب Metasploit.

## المميزات
- **لوحة معلومات متطورة**: مبنية باستخدام React و Tailwind CSS.
- **دعم ثنائي اللغة**: تبديل سلس بين العربية والإنجليزية.
- **دفاع نشط**: حظر تلقائي للتهديدات عالية الخطورة.
- **شرح الذكاء الاصطناعي (SHAP)**: توضيح أسباب اتخاذ القرار من قبل النظام.
