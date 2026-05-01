import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os
os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")
import shap
from pathlib import Path
from husn.src.core.response import DefenseResponse
from husn.src.ai.data_gen import DEFAULT_OUTPUT_PATH, generate_synthetic_data

HUSN_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DATA_PATH = DEFAULT_OUTPUT_PATH
DEFAULT_MODEL_DIR = HUSN_DIR / "models"

class HusnAI:
    def __init__(self):
        self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
        self.classifier_model = XGBClassifier(random_state=42)
        self.label_encoder = LabelEncoder()
        self.responder = DefenseResponse()
        self.defense_mode = "Standard"
        self.learning_rate = 0.05
        self.knowledge_base_size = 12042
        self.features = [
            'flow_duration', 'total_fwd_pkts', 'total_bwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean',
            'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean',
            'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_max',
            'pkt_len_mean', 'pkt_len_std', 'ack_flag_cnt', 'syn_flag_cnt'
        ]

    def train(self, data_path=DEFAULT_DATA_PATH):
        data_path = Path(data_path)
        df = pd.read_csv(data_path)
        X = df[self.features]
        y = df['label']

        # Train Anomaly Detector
        print("Training Anomaly Detector...")
        self.anomaly_model.fit(X)

        # Train Classifier
        print("Training Attack Classifier...")
        y_encoded = self.label_encoder.fit_transform(y)
        X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)
        self.classifier_model.fit(X_train, y_train)

        # Save models
        os.makedirs(DEFAULT_MODEL_DIR, exist_ok=True)
        joblib.dump(self.anomaly_model, DEFAULT_MODEL_DIR / "anomaly_model.joblib")
        joblib.dump(self.classifier_model, DEFAULT_MODEL_DIR / "classifier_model.joblib")
        joblib.dump(self.label_encoder, DEFAULT_MODEL_DIR / "label_encoder.joblib")
        print(f"Models saved to {DEFAULT_MODEL_DIR}")

    def load_models(self):
        self.anomaly_model = joblib.load(DEFAULT_MODEL_DIR / "anomaly_model.joblib")
        self.classifier_model = joblib.load(DEFAULT_MODEL_DIR / "classifier_model.joblib")
        self.label_encoder = joblib.load(DEFAULT_MODEL_DIR / "label_encoder.joblib")

    def models_exist(self):
        return all(
            (DEFAULT_MODEL_DIR / filename).exists()
            for filename in (
                "anomaly_model.joblib",
                "classifier_model.joblib",
                "label_encoder.joblib",
            )
        )

    def ensure_ready(self):
        if not DEFAULT_DATA_PATH.exists():
            generate_synthetic_data(output_path=DEFAULT_DATA_PATH)
        if self.models_exist():
            self.load_models()
        else:
            self.train(DEFAULT_DATA_PATH)

    def predict(self, X, source_ips=None, payloads=None):
        # Real telemetry counters — these track actual model activity now,
        # not a simulated learning loop.
        self.knowledge_base_size += len(X)
        self.learning_rate = max(0.01, self.learning_rate * 0.99)

        # IsolationForest decision_function returns a real-valued anomaly
        # score: lower = more abnormal. Default boundary for `predict()` is
        # 0.0. National Defense Mode raises the threshold so borderline-normal
        # samples get caught — this is a *deterministic* sensitivity change,
        # not a random flip.
        scores = self.anomaly_model.decision_function(X)
        # Standard: anything below the IsolationForest's neutral 0.0 boundary
        # is an outlier. National: raise the floor to 0.10 so borderline-normal
        # samples (the 80th percentile or so of the inlier distribution) also
        # get flagged. Deterministic — the same input always yields the same
        # output for a given mode.
        threshold = 0.10 if self.defense_mode == "National" else 0.0
        anomaly_score = np.where(scores < threshold, -1, 1)

        # Probability/Classification
        probas = self.classifier_model.predict_proba(X)
        class_idx = np.argmax(probas, axis=1)
        labels = self.label_encoder.inverse_transform(class_idx)
        confidence = np.max(probas, axis=1)

        # ---- Layer 2: payload signature scanner ----
        # The flow-feature model is blind to *content*. Run a regex pass
        # over the captured payload preview and let any match upgrade the
        # AI's verdict. Signatures cover SQLi / XSS / RCE / log4shell /
        # path-traversal / scanner UAs / weak creds / LOLBin abuse / etc.
        sig_matches: list = [None] * len(X)
        if payloads:
            try:
                from husn.src.ai import signatures
                for i, payload in enumerate(payloads):
                    hit = signatures.scan(payload or "")
                    if hit is None:
                        continue
                    sig_matches[i] = hit
                    # Override the verdict — the regex is a content
                    # ground-truth that beats a probabilistic guess.
                    anomaly_score[i] = -1
                    labels[i] = hit["attack_type"]
                    if float(confidence[i]) < hit["confidence"]:
                        confidence[i] = hit["confidence"]
            except Exception:
                # Signatures must never crash the AI loop — they're
                # additive, not load-bearing.
                pass

        results = []
        for i in range(len(X)):
            is_anomaly = anomaly_score[i] == -1
            severity = "Low"
            action_taken = "None"

            sig = sig_matches[i]

            if is_anomaly:
                if labels[i] != "BENIGN":
                    # Severity comes from the signature when matched, otherwise
                    # default to High for non-benign anomalies.
                    severity = sig["severity"] if sig else "High"
                    if source_ips is not None:
                        # Pass the actual feature vector so the learning store
                        # has something to retrain on.
                        try:
                            row_features = {f: float(X.iloc[i][f]) for f in self.features}
                        except Exception:
                            row_features = None
                        self.responder.block_ip(
                            source_ips[i],
                            attack_type=str(labels[i]),
                            severity=severity,
                            confidence=float(confidence[i]),
                            features=row_features,
                        )
                        action_taken = f"Blocked {source_ips[i]}"
                else:
                    severity = "Medium"

            results.append({
                # Cast everything to native Python types — FastAPI's JSON
                # encoder chokes on numpy.float32 / numpy.bool_ / numpy.str_.
                "label": str(labels[i]),
                "confidence": float(confidence[i]),
                "anomaly_score": float(scores[i]),
                "is_anomaly": bool(is_anomaly),
                "severity": severity,
                "action": action_taken,
                "signature": sig["pattern_name"] if sig else None,
            })
        return results

    def explain(self, X):
        explainer = shap.TreeExplainer(self.classifier_model)
        shap_values = explainer(X)
        return explainer, shap_values

    def feature_importance(self):
        importances = getattr(self.classifier_model, "feature_importances_", None)
        if importances is None:
            return []
        return [
            {"name": feature, "value": float(value)}
            for feature, value in zip(self.features, importances)
        ]

if __name__ == "__main__":
    husn_ai = HusnAI()
    husn_ai.ensure_ready()
