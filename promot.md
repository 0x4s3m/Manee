# 🛡️ Husn (حصن) - Developer & Judge's Guide

This document provides a deep technical breakdown of **Husn (حصن)** for developers and the DefensThon 2026 judging panel.

## 🏗️ Architecture Overview

Husn follows a modern, decoupled architecture:

1.  **Frontend (React + TypeScript + Vite)**:
    *   **Tech Stack**: Tailwind CSS, Framer Motion (animations), Recharts (visualization), Lucide (icons).
    *   **Localization**: Bilingual EN/AR support integrated via a custom i18n object.
    *   **SIEM Intelligence Feed**: Real-time log visualization and threat mapping.

2.  **Backend (FastAPI)**:
    *   **Core API**: Manages system state, simulation requests, and log aggregation.
    *   **Cyber-Intelligence**: Exposes AI prediction and SHAP interpretability endpoints.

3.  **AI Engine (Hybrid ML)**:
    *   **Anomaly Detection**: `IsolationForest` identifies zero-day or non-signature-based deviations.
    *   **Classification**: `XGBoost` categorizes attacks into: DDoS, PortScan, Brute Force, Infiltration, or Web Attacks.
    *   **SHAP Integration**: Calculates feature importance (Lundberg values) to provide transparency into model decisions.

4.  **Network Engine (Scapy)**:
    *   Handles low-level packet crafting for realistic simulations.
    *   Implements stealth probing and data exfiltration signatures.

---

## 🧪 Technical Demo Flow (How to win)

To demonstrate the full power of Husn, use the following sequence:

### 1. The Setup
Run `./setup.sh` to ensure all OS-level capabilities (`setcap`) and dependencies are ready.

### 2. The Command Center
Start the system using `python run.py both`. This launches:
*   **Backend** (Port 8000)
*   **Frontend** (Port 5173)
*   **Vulnerable Target** (Port 9000)
*   **Interactive CLI** (Terminal)

### 3. The "Infiltration" Event (RCE)
1.  Navigate to the **Attack Simulation** tab on the Dashboard.
2.  Click the red **"RCE EXPLOIT"** button.
3.  **Backend Action**: Husn triggers a real command injection against `vuln_app.py` and simultaneously sends network flows with malicious signatures.
4.  **Detection**: Watch the SIEM feed on the dashboard. You will see an **"Infiltration"** alert with high confidence.
5.  **Active Defense**: The logs will show: `ACTIVE DEFENSE: Blocking malicious IP...`. The IP is instantly isolated.

### 4. Explainable AI
*   Switch to the **Explainable AI (SHAP)** tab.
*   Click **"Run SHAP Engine"**.
*   Show the judges the chart: "We detected the RCE because the 'Packet Length Mean' and 'TCP Flags' matched our infiltration training set."

---

## 🔧 Novelty Features

### 🛡️ National Defense Mode
Implemented as a state-machine in `backend/husn/src/ai/model.py`. When active:
*   Detection sensitivity is artificially boosted (lower threshold for anomalies).
*   Logging frequency increases.
*   UI theme shifts to "Critical" (Red) mode.

### 🧠 Adaptive Self-Learning
Simulates a real-world learning loop:
*   The `knowledge_base_size` increments with every processed packet.
*   The `learning_rate` decays over time, mimicking model convergence.

---

## 🚀 Portability Notes
Husn is designed for headless servers. Use `docker-compose up --build` for cloud deployment, or `python run.py both` for a local Kali Linux demonstration.
