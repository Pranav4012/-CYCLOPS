"""Explainable heuristic scoring layered above calibrated detector confidence."""
from __future__ import annotations

from typing import Any


def score_incident(detections: list[dict[str, Any]]) -> dict[str, Any]:
    """Return an explicitly heuristic incident threat score in [0, 100]."""
    if not detections:
        return {"threat_score": 0, "score_type": "heuristic", "severity": "info"}
    confidence = max(float(item.get("confidence", 0.0)) for item in detections)
    independent = len({item.get("detector", "unknown") for item in detections})
    score = min(100, round(confidence * 70 + min(30, (independent - 1) * 15)))
    if score >= 85:
        severity = "critical"
    elif score >= 70:
        severity = "high"
    elif score >= 50:
        severity = "medium"
    elif score >= 30:
        severity = "low"
    else:
        severity = "info"
    return {"threat_score": score, "score_type": "heuristic",
            "severity": severity, "independent_detectors": independent}
