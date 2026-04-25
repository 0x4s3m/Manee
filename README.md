# Husn (حصن) - Intelligent Cyber Shield (Final Polish)

<div align="center">
  <h3>Intelligent Cyber Defense System for National Security</h3>
  <p><b>DefensThon 2026 - Official Submission</b></p>
</div>

Husn (حصن) is a state-of-the-art AI-powered cybersecurity system designed for high-portability and professional-grade defense. It features an adaptive AI engine, a modern React dashboard, and realistic attack simulations.

---

## 🚀 One-Command Setup (Universal)

Husn is designed to run on **Kali Linux, Ubuntu, Debian, CentOS, RHEL, and WSL2**.

```bash
chmod +x setup.sh
./setup.sh
```

This script detects your OS, installs system dependencies (Python, Node.js, Scapy libs), sets up virtual environments, and configures raw socket permissions.

---

## 🐳 Docker Deployment

For containerized environments, use Docker Compose:

```bash
docker-compose up --build
```

The system will be available at:
- **Dashboard**: `http://localhost:5173`
- **Backend API**: `http://localhost:8000`

---

## ✨ Features (v9 Final)

- **🛡️ National Defense Mode**: One-click system-wide sensitivity boost. Increases anomaly detection thresholds and triggers aggressive logging.
- **🧠 Adaptive Self-Learning**: AI engine that simulates real-time knowledge base growth and learning rate decay based on processed traffic.
- **🚀 High-Professional Dashboard**: Built with **React + TypeScript + Framer Motion**, featuring neon-cyber aesthetics.
- **🔍 Explainable AI (SHAP)**: Visual feature importance plots explaining AI decisions.
- **🌍 Full Bilingual Support**: Seamless English and Arabic interface.
- **📡 Realistic Simulation**: Scapy-powered DDoS, Port Scan, and Brute Force simulations for live demos.

---

## 🏆 Live Demo Guide (For Judges)

To deliver an impressive demonstration, follow these steps:

### 1. Preparation
Ensure all dependencies are installed using `./setup.sh`.

### 2. The Launch
Run the dual-mode system to show both the CLI and the Web Dashboard simultaneously:
```bash
python run.py both
```
*   **Narrative**: "We start with our dual-interface approach: a high-speed terminal for operators and a modern command center for decision-makers."

### 3. The Dashboard (Bilingual & Real-time)
*   Open `http://localhost:5173`.
*   Toggle the **Arabic/English** button to show localization.
*   Point out the **Real-time Monitoring** graphs and the **Adaptive Self-Learning** cards showing the KB Size growing.

### 4. The Attack Simulation (The Climax)
*   Go to the **Attack Simulation** section.
*   Select **"DDoS Attack"** or **"SSH Brute Force"**.
*   Click **"Simulate"**.
*   **Switch to the Terminal**: Show the Scapy packets flooding the console.
*   **Back to Dashboard**: Watch the **"Malicious"** traffic spike and the **Active Shield** logs automatically blocking the source IP.

### 5. Explainable AI (SHAP)
*   Navigate to **Explainable AI**.
*   Click **"Run SHAP Engine"**.
*   **Narrative**: "Judges, Husn doesn't just block; it explains. Here we see exactly which network features (like Packet Length or Inter-arrival Time) triggered our AI's decision."

### 6. National Defense Mode
*   Toggle the **"National Defense Mode"** button.
*   Watch the UI turn red and detection sensitivity increase.
*   **Narrative**: "In times of crisis, our National Defense Mode hardens the infrastructure instantly, prioritizing security over latency."

---

## 🛠️ Manual Usage

Launch the full system:
```bash
python run.py both
```

Or individual components:
- `python run.py cli`
- `python run.py backend`
- `python run.py frontend`

---

# حصن (Husn) - الدرع السيبراني الذكي

حصن هو نظام للأمن السيبراني مدعوم بالذكاء الاصطناعي تم تطويره لمسابقة DefensThon 2026. يتميز النظام بلوحة معلومات احترافية مبنية على React وواجهة سطر أوامر متطورة.

## المميزات الأساسية
- **وضع الدفاع الوطني**: تعزيز حساسية النظام بضغطة واحدة لمواجهة التهديدات الحرجة.
- **التعلم الذاتي التكيفي**: محرك ذكاء اصطناعي يحاكي النمو المستمر لقاعدة المعرفة.
- **لوحة معلومات متطورة**: مبنية باستخدام React و Tailwind CSS بدعم كامل للغة العربية.
- **شرح الذكاء الاصطناعي (SHAP)**: توضيح أسباب اتخاذ القرار من قبل النظام لضمان الشفافية.
