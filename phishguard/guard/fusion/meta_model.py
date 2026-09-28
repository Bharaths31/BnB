"""Fusion meta-model: calibrated probability + decision levels (WS7).

Threshold values are loaded from ``data/processed/calibrated_policy.json`` when present (the
artifact produced by ``scripts/calibrate_thresholds.py``) and otherwise fall back to the safe
defaults in ``config/policy.yaml``. Probability calibration is an identity map placeholder
until an isotonic artifact is produced, so the field is always populated and meaningful.
"""
from __future__ import annotations

import json
import os
from typing import Dict, Optional

from guard.config import policy


def _default_thresholds() -> Dict[str, float]:
    thresholds = policy.get("thresholds", {})
    fusion = policy.get("fusion", {})
    return {
        "block": float(thresholds.get("block", 0.85)),
        "flag": float(thresholds.get("flag", 0.50)),
        "review": float(fusion.get("review_threshold", 0.70)),
        "uncertainty_gate": float(fusion.get("uncertainty_review_gate", 0.60)),
    }


def _calibration_path() -> str:
    configured = policy.get("models", {}).get("calibration_policy")
    if configured:
        return configured
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "data", "processed", "calibrated_policy.json")


class MetaModel:
    def __init__(self, calibration_path: Optional[str] = None):
        self.thresholds = _default_thresholds()
        self.calibration_method = "identity"
        self._load_calibration(calibration_path or _calibration_path())

    def _load_calibration(self, path: str) -> None:
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            return
        for key in ("block_threshold", "flag_threshold", "review_threshold"):
            if key in data:
                self.thresholds[key.replace("_threshold", "")] = float(data[key])
        if "uncertainty_gate" in data:
            self.thresholds["uncertainty_gate"] = float(data["uncertainty_gate"])
        self.calibration_method = data.get("calibration_method", "calibrated_policy.json")

    # ------------------------------------------------------------------ calibration
    def calibrate(self, raw_score: float) -> float:
        """Map a raw score to a calibrated probability in [0, 1]."""
        return max(0.0, min(1.0, float(raw_score)))

    # --------------------------------------------------------------------- decision
    def decide(self, calibrated_probability: float, uncertainty: float) -> str:
        """ALLOW / FLAG / REVIEW / BLOCK.

        REVIEW captures high-risk *and* high-uncertainty cases: the system believes the mail
        is dangerous but the components disagree, so a human should look before an automatic
        block. Uncertainty never replaces the risk score.
        """
        block = self.thresholds["block"]
        flag = self.thresholds["flag"]
        gate = self.thresholds["uncertainty_gate"]

        if calibrated_probability >= block:
            return "REVIEW" if uncertainty >= gate else "BLOCK"
        if calibrated_probability >= self.thresholds["review"] and uncertainty >= gate:
            return "REVIEW"
        if calibrated_probability >= flag:
            return "FLAG"
        return "ALLOW"


meta_model = MetaModel()

__all__ = ["MetaModel", "meta_model"]
