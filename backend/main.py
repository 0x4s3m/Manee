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

class ScanRequest(BaseModel):
    target: str

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

@app.post("/scan")
def run_scan(req: ScanRequest):
    logs.append(f"[{time.strftime('%H:%M:%S')}] SCAN STARTED: Targeting {req.target}")
    # Simulate a real scan return with a delay (handled by frontend, but we prepare data)
    sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(5)
    X = sample_df[ai.features]

    results = ai.predict(X)
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
    return logs[-30:]

@app.get("/explain")
def get_explanation():
    sample_df = pd.read_csv("husn/data/synthetic_traffic.csv").sample(1)
    X = sample_df[ai.features]
    explainer, shap_values = ai.explain(X)

    feature_importance = []
    # Handle both new and old SHAP API outputs
    if hasattr(shap_values, 'values'):
        vals = shap_values.values[0]
        base = float(shap_values.base_values[0])
    else:
        vals = shap_values[0]
        base = 0.5

    for i, feat in enumerate(ai.features):
        feature_importance.append({
            "name": feat,
            "value": float(vals[i])
        })

    feature_importance.sort(key=lambda x: abs(x['value']), reverse=True)

    return {
        "features": feature_importance[:10],
        "base_value": base
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
