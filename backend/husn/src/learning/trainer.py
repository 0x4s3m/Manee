"""Retrain the XGBoost classifier using synthetic data + confirmed blocks.

`retrain()`:
  1. loads the synthetic training CSV (the seed dataset)
  2. appends every event in `block_events` marked feedback='confirmed'
     as a new labelled sample
  3. retrains the classifier, evaluates accuracy on a held-out 20% split
  4. swaps the classifier in the live HusnAI singleton + persists the joblib
  5. logs the run to `training_runs`

Designed to be safe to call concurrently with predict() — the swap is
atomic (one attribute assignment).
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from husn.src.ai.model import DEFAULT_DATA_PATH, DEFAULT_MODEL_DIR
from husn.src.learning import store

log = logging.getLogger("husn.learning.trainer")


def retrain(ai, source: str = "manual") -> dict[str, Any]:
    """Retrain `ai.classifier_model` (in place) using base CSV + confirmed events.

    `ai` is the HusnAI singleton; we pass it explicitly so we don't import
    main here (would be a cycle)."""
    t0 = time.perf_counter()
    base = pd.read_csv(DEFAULT_DATA_PATH)
    extra_pairs = store.confirmed_features()

    if extra_pairs:
        rows = []
        for feats, label in extra_pairs:
            row = {f: feats.get(f, 0) for f in ai.features}
            row["label"] = label or "BENIGN"
            rows.append(row)
        extra_df = pd.DataFrame(rows)
        df = pd.concat([base, extra_df], ignore_index=True)
    else:
        df = base

    X = df[ai.features]
    y = df["label"]

    # Refit the label encoder on the union (in case feedback added a new label)
    y_enc = ai.label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42)
    new_clf = XGBClassifier(random_state=42)
    new_clf.fit(X_train, y_train)
    acc = float(accuracy_score(y_test, new_clf.predict(X_test)))

    # Persist + atomic swap
    DEFAULT_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = DEFAULT_MODEL_DIR / "classifier_model.joblib.bak"
    target_path = DEFAULT_MODEL_DIR / "classifier_model.joblib"
    if target_path.exists():
        target_path.replace(backup_path)
    joblib.dump(new_clf, target_path)
    joblib.dump(ai.label_encoder, DEFAULT_MODEL_DIR / "label_encoder.joblib")
    ai.classifier_model = new_clf  # atomic — predict() reads this attr per call

    duration_ms = int((time.perf_counter() - t0) * 1000)
    run_id = store.record_training_run(
        total_samples=int(len(df)),
        confirmed_count=int(len(extra_pairs)),
        accuracy=acc,
        duration_ms=duration_ms,
        source=source,
        notes=f"features={len(ai.features)}, classes={len(set(y))}",
    )

    # Update the AI's "real" telemetry counters.
    ai.knowledge_base_size = int(len(df))
    ai.learning_rate = round(acc, 4)

    log.info("[trainer] retrain done — samples=%d  +%d confirmed  acc=%.4f  %dms",
             len(df), len(extra_pairs), acc, duration_ms)
    return {
        "run_id": run_id,
        "total_samples": int(len(df)),
        "confirmed_count": int(len(extra_pairs)),
        "accuracy": acc,
        "duration_ms": duration_ms,
        "source": source,
    }
