import unittest
import pandas as pd
from husn.src.ai.model import DEFAULT_DATA_PATH, HusnAI
from husn.src.core.simulator import AttackSimulator

class TestHusn(unittest.TestCase):
    def setUp(self):
        self.ai = HusnAI()
        self.ai.ensure_ready()
        self.data_path = DEFAULT_DATA_PATH

    def test_ai_prediction(self):
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
        df = pd.read_csv(self.data_path).head(1)
        X = df[self.ai.features]
        explainer, shap_values = self.ai.explain(X)
        self.assertIsNotNone(explainer)
        self.assertIsNotNone(shap_values)

if __name__ == "__main__":
    unittest.main()
