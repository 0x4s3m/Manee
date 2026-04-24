from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import time
import os
import random

from husn.src.ai.model import HusnAI
from husn.src.core.simulator import AttackSimulator
from husn.src.core.response import DefenseResponse

app = FastAPI(title="Husn API")

# Enable CORS for React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State
ai = HusnAI()
if os.path.exists("husn/models/classifier_model.joblib"):
    ai.load_models()

logs = []

class SimulationRequest(BaseModel):
    target_ip: str
    attack_type: str

@app.get("/status")
def get_status():
    return {
        "ai_engine": "online",
        "network_monitor": "active",
        "shield": "active",
        "threat_level": "low"
    }

@app.get("/monitor")
def get_monitoring_data():
    return {
        "timestamp": time.time(),
        "incoming": random.randint(100, 1000),
        "outgoing": random.randint(50, 500),
        "malicious": random.randint(0, 5),
        "uptime": "99.9%",
        "threats_blocked": 1284 + len([l for l in logs if "BLOCK" in l])
    }

@app.get("/scan")
def run_scan():
    # Simulate a real scan return
    sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(10)
    X = sample_df[ai.features]

    source_ips = [f"192.168.1.{random.randint(1,254)}" for _ in range(len(X))]
    # Occasional threat
    if random.random() > 0.7:
        source_ips[random.randint(0,9)] = f"{random.randint(1,255)}.{random.randint(1,255)}.x.y"

    results = ai.predict(X, source_ips=source_ips)

    for res, ip in zip(results, source_ips):
        if res['severity'] == "High":
            logs.append(f"[{time.strftime('%H:%M:%S')}] ALERT: BLOCKING {ip} due to {res['label']}")
        else:
            logs.append(f"[{time.strftime('%H:%M:%S')}] INFO: Packet from {ip} analyzed... OK")

    return results

@app.post("/simulate")
def trigger_simulation(req: SimulationRequest):
    sim = AttackSimulator(req.target_ip)
    if "DDoS" in req.attack_type:
        sim.ddos_simulation(count=20)
    elif "Port" in req.attack_type:
        sim.port_scan_simulation()
    else:
        sim.brute_force_simulation()

    logs.append(f"[{time.strftime('%H:%M:%S')}] SIMULATION: {req.attack_type} launched against {req.target_ip}")
    return {"status": "success", "message": f"Simulation of {req.attack_type} completed."}

@app.get("/logs")
def get_logs():
    return logs[-20:]

@app.get("/explain")
def get_explanation():
    sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(1)
    X = sample_df[ai.features]
    explainer, shap_values = ai.explain(X)

    # Format SHAP data for React frontend
    # Since we can't easily send complex matplotlib/shap objects,
    # we send raw values for Recharts.
    feature_importance = []
    base_values = shap_values.base_values[0] if hasattr(shap_values, 'base_values') else 0
    values = shap_values.values[0] if hasattr(shap_values, 'values') else shap_values[0]

    for i, feat in enumerate(ai.features):
        feature_importance.append({
            "name": feat,
            "value": float(values[i])
        })

    # Sort by absolute value
    feature_importance.sort(key=lambda x: abs(x['value']), reverse=True)

    return {
        "features": feature_importance[:10],
        "base_value": float(base_values)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
