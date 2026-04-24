import unittest
import os
import pandas as pd
from husn.src.ai.model import HusnAI
from husn.src.core.simulator import AttackSimulator

class TestHusn(unittest.TestCase):
    def setUp(self):
        self.ai = HusnAI()
        if os.path.exists("husn/models/classifier_model.joblib"):
            self.ai.load_models()
        self.data_path = "husn/data/synthetic_traffic.csv"

    def test_ai_prediction(self):
        if not os.path.exists(self.data_path):
            self.skipTest("Synthetic data not found")

        df = pd.read_csv(self.data_path).head(5)
        X = df[self.ai.features]
        results = self.ai.predict(X)
        self.assertEqual(len(results), 5)
        self.assertIn("label", results[0])
        self.assertIn("severity", results[0])

    def test_simulator_init(self):
        sim = AttackSimulator("127.0.0.1")
        self.assertEqual(sim.target_ip, "127.0.0.1")

    def test_ai_explain(self):
        if not os.path.exists(self.data_path):
            self.skipTest("Synthetic data not found")

        df = pd.read_csv(self.data_path).head(1)
        X = df[self.ai.features]
        explainer, shap_values = self.ai.explain(X)
        self.assertIsNotNone(explainer)
        self.assertIsNotNone(shap_values)

if __name__ == "__main__":
    unittest.main()
