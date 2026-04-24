import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import shap
import os

class HusnAI:
    def __init__(self):
        self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
        self.classifier_model = XGBClassifier(random_state=42)
        self.label_encoder = LabelEncoder()
        self.features = [
            'flow_duration', 'total_fwd_pkts', 'total_bwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean',
            'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean',
            'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_max',
            'pkt_len_mean', 'pkt_len_std', 'ack_flag_cnt', 'syn_flag_cnt'
        ]

    def train(self, data_path):
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
        os.makedirs("husn/models", exist_ok=True)
        joblib.dump(self.anomaly_model, "husn/models/anomaly_model.joblib")
        joblib.dump(self.classifier_model, "husn/models/classifier_model.joblib")
        joblib.dump(self.label_encoder, "husn/models/label_encoder.joblib")
        print("Models saved to husn/models/")

    def load_models(self):
        self.anomaly_model = joblib.load("husn/models/anomaly_model.joblib")
        self.classifier_model = joblib.load("husn/models/classifier_model.joblib")
        self.label_encoder = joblib.load("husn/models/label_encoder.joblib")

    def predict(self, X):
        # 1 means normal, -1 means anomaly
        anomaly_score = self.anomaly_model.predict(X)

        # Probability/Classification
        probas = self.classifier_model.predict_proba(X)
        class_idx = np.argmax(probas, axis=1)
        labels = self.label_encoder.inverse_transform(class_idx)
        confidence = np.max(probas, axis=1)

        results = []
        for i in range(len(X)):
            is_anomaly = anomaly_score[i] == -1
            severity = "Low"
            if is_anomaly:
                if labels[i] != "BENIGN":
                    severity = "High"
                else:
                    severity = "Medium"

            results.append({
                "label": labels[i],
                "confidence": confidence[i],
                "is_anomaly": is_anomaly,
                "severity": severity
            })
        return results

    def explain(self, X):
        explainer = shap.TreeExplainer(self.classifier_model)
        shap_values = explainer.shap_values(X)
        return explainer, shap_values

if __name__ == "__main__":
    husn_ai = HusnAI()
    husn_ai.train("husn/data/synthetic_traffic.csv")
