# Husn (حصن) - Intelligent Cyber Shield

<div align="center">
  <img src="https://raw.githubusercontent.com/username/repo/main/assets/husn_logo.png" alt="Husn Logo" width="200"/>
  <h3>Intelligent Cyber Defense System for National Security</h3>
</div>

Husn (حصن) is an AI-powered cybersecurity system designed for the DefensThon 2026 competition. It provides real-time network monitoring, threat detection, and automated attack response with explainable AI.

---

## 📸 Screenshots

### 🛠️ Professional CLI (Metasploit Style)
![CLI Screenshot](assets/cli_screenshot.png)

### 📊 Bilingual Web Dashboard
![Dashboard English](assets/dashboard_en.png)

---

## 📁 Project Structure
```
husn/
├── data/               # Datasets
├── models/             # Trained AI models
├── src/
│   ├── ai/             # AI Model, SHAP logic, Data Gen
│   ├── core/           # Attack Simulation & Active Defense
│   ├── cli.py          # Interactive CLI (Enchanted)
│   └── dashboard.py    # Streamlit Dashboard (Enchanted)
└── tests/              # Unit tests
run.py                  # Dual-mode entry point
```

## ✨ Features
- **Dual Interface**: Run the high-tech CLI and the bilingual Web Dashboard concurrently.
- **Active Defense**: Automated IP blocking and session termination for high-severity threats.
- **Professional CLI**: Metasploit-style interactive shell with boot sequences and live monitors.
- **Web Dashboard**: Neon-themed Streamlit dashboard with real-time SIEM logs and SHAP visualizations.
- **AI-Powered**: Hybrid XGBoost + IsolationForest models trained on network flow data.

## 🚀 Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Usage
Launch Husn using the `run.py` script:

- **Full Experience (Dual Mode)**:
  ```bash
  python run.py both
  ```
- **Interactive CLI Only**:
  ```bash
  python run.py cli
  ```
- **Web Dashboard Only**:
  ```bash
  python run.py dashboard
  ```

---

# حصن (Husn) - الدرع السيبراني الذكي

حصن هو نظام للأمن السيبراني مدعوم بالذكاء الاصطناعي تم تطويره لمسابقة DefensThon 2026. يوفر النظام مراقبة الشبكة في الوقت الفعلي، واكتشاف التهديدات، والاستجابة التلقائية للهجمات مع شرح الذكاء الاصطناعي.

## المميزات
- **الاستخدام المزدوج**: تشغيل واجهة سطر الأوامر ولوحة المعلومات في وقت واحد.
- **الدفاع النشط**: حظر تلقائي لعناوين IP المهاجمة.
- **واجهة سطر الأوامر (CLI)**: واجهة احترافية بأسلوب Metasploit مع مراقبة حية.
- **لوحة معلومات الويب**: لوحة Streamlit ثنائية اللغة (العربية/الإنجليزية) بمظهر مستقبلي.

## الاستخدام
- **الوضع المزدوج**: `python run.py both`
- **واجهة سطر الأوامر**: `python run.py cli`
- **لوحة التحكم**: `python run.py dashboard`
