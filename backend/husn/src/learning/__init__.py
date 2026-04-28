"""Adaptive Self-Learning — real version.

Every block event the responder fires is logged to a SQLite store along
with the feature vector the AI used for the decision. Admins mark events
as "Confirmed" or "False positive" via the dashboard. A scheduled
trainer combines the synthetic CSV + confirmed events to retrain the
XGBoost classifier overnight (or on demand).

`learning_rate` and `knowledge_base_size` in /status now reflect REAL
metrics: the size of the cumulative training set, and the rolling
accuracy of the last 5 retrains.
"""
