from __future__ import annotations

from pathlib import Path

import numpy as np

_MODEL_PATH = Path(__file__).parent / "dga_model.npz"

_model_cache: dict | None = None


def _load_model() -> dict | None:
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    if not _MODEL_PATH.exists():
        return None
    data = np.load(_MODEL_PATH, allow_pickle=True)
    _model_cache = {
        "weights": data["weights"],
        "bias": float(data["bias"]),
        "vocab": list(data["vocab"]),
    }
    return _model_cache


def _char_ngram_features(label: str, vocab: list[str], n: int = 2) -> np.ndarray:
    ngrams = [label[i:i + n] for i in range(len(label) - n + 1)]
    counts = {g: ngrams.count(g) for g in set(ngrams)}
    total = max(len(ngrams), 1)
    return np.array([counts.get(g, 0) / total for g in vocab])


def model_score(label: str) -> float | None:
    """
    Returns a 0-1 probability that `label` is DGA-generated, using the
    trained model. Returns None if no trained model is available, so
    callers (babel.py) know to fall back to the heuristic score instead
    of silently treating "no model" as "score 0".
    """
    model = _load_model()
    if model is None:
        return None

    features = _char_ngram_features(label.lower(), model["vocab"])
    logit = float(np.dot(features, model["weights"]) + model["bias"])
    probability = 1.0 / (1.0 + np.exp(-logit))
    return round(probability, 3)


def is_model_available() -> bool:
    return _MODEL_PATH.exists()