"""Metric helpers: precision/recall/F1, relative error, calibration gap."""
from __future__ import annotations

from typing import List, Dict
import math


def prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def rel_errors(pred: List[float], truth: List[float]) -> List[float]:
    return [abs(p - t) / t for p, t in zip(pred, truth) if t > 0]


def summary_stats(xs: List[float]) -> Dict[str, float]:
    if not xs:
        return {"n": 0}
    s = sorted(xs); n = len(s)
    mean = sum(s) / n
    var = sum((x - mean) ** 2 for x in s) / n
    def q(p): return s[min(n - 1, int(p * n))]
    return {"n": n, "mean": mean, "std": math.sqrt(var),
            "median": q(0.5), "p90": q(0.9), "p95": q(0.95), "max": s[-1], "min": s[0]}


def mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0
