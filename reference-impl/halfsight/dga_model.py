"""
Trained DGA classifier — character n-gram logistic regression (numpy only).

This is the real-data upgrade to the hand-tuned heuristic in detectors/dga.py.
It learns from a labeled corpus of REAL DGA domains (25 published families) vs
REAL benign domains (Alexa / OpenDNS top lists), using hashed character 1/2/3-grams
plus a handful of statistical features. Weights train with mini-batch SGD and
serialize to a small .npz that BABEL loads at runtime — no dataset needed to run.

Stable (process-independent) hashing so a saved model scores identically anywhere.
"""
from __future__ import annotations

import os
from typing import List, Tuple, Optional

import numpy as np

from .types import shannon_entropy

VOWELS = set("aeiou")
NGRAMS = (1, 2, 3, 4)
N_STAT = 6
DEFAULT_DIM = 16384
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "dga_model.npz")


def registrable_label(domain: str) -> str:
    """The DGA-bearing label — leftmost label (where the generated string lives)."""
    d = domain.strip().strip(".").lower()
    if not d:
        return ""
    return d.split(".")[0]


def _fnv1a(s: str) -> int:
    h = 2166136261
    for ch in s.encode("utf-8", "ignore"):
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def _stat_features(label: str) -> List[float]:
    n = len(label) or 1
    digits = sum(c.isdigit() for c in label)
    alpha = sum(c.isalpha() for c in label) or 1
    vowels = sum(c in VOWELS for c in label if c.isalpha())
    run = maxrun = 0
    for c in label:
        if c.isalpha() and c not in VOWELS:
            run += 1; maxrun = max(maxrun, run)
        else:
            run = 0
    uniq = len(set(label)) / n
    return [min(1.0, n / 30.0), min(1.0, shannon_entropy(label) / 5.0),
            digits / n, vowels / alpha, uniq, min(1.0, maxrun / 10.0)]


def ngram_indices(label: str, dim: int) -> List[int]:
    idx = []
    for n in NGRAMS:
        for i in range(len(label) - n + 1):
            idx.append(_fnv1a(label[i:i + n]) % dim)
    return idx


class DGAModel:
    """
    Embedding-bag MLP over hashed char n-grams + stat features (fastText-style).

    The first layer is sparse: a domain's hidden pre-activation is the SUM of the
    embedding rows for its active n-grams (plus a small dense contribution from the
    6 statistical features), so training and inference only ever touch the ~dozens
    of features a domain actually has — fast in pure numpy, no framework.
    """

    def __init__(self, dim: int = DEFAULT_DIM, hidden: int = 256):
        self.dim = dim
        self.H = hidden
        rng = np.random.default_rng(0)
        self.W1 = (rng.standard_normal((dim + N_STAT, hidden)) * 0.05).astype(np.float32)
        self.b1 = np.zeros(hidden, dtype=np.float32)
        self.W2 = np.zeros(hidden, dtype=np.float32)
        self.b2 = 0.0
        self.threshold = 0.5
        self.trained = False

    # ---- forward ----------------------------------------------------------
    def _hidden(self, label: str) -> np.ndarray:
        idx = ngram_indices(label, self.dim)
        h = self.W1[idx].sum(axis=0) if idx else np.zeros(self.H, dtype=np.float32)
        stats = np.asarray(_stat_features(label), dtype=np.float32)
        h = h + stats @ self.W1[self.dim:self.dim + N_STAT] + self.b1
        return np.maximum(0.0, h)

    def prob(self, domain: str) -> float:
        label = registrable_label(domain)
        if len(label) < 4:
            return 0.0
        z = float(self._hidden(label) @ self.W2 + self.b2)
        return 1.0 / (1.0 + np.exp(-z))

    def is_dga(self, domain: str) -> bool:
        return self.prob(domain) >= self.threshold

    def scores(self, domains: List[str]) -> np.ndarray:
        return np.array([self.prob(x) for x in domains])

    # ---- training (mini-batch SGD, dense batches — BLAS accelerated) ------
    def fit(self, labels: List[str], y: np.ndarray, epochs: int = 16,
            lr: float = 0.2, l2: float = 1e-6, batch: int = 512, seed: int = 0,
            verbose: bool = False) -> "DGAModel":
        import sys
        rng = np.random.default_rng(seed)
        idx_lists = [np.asarray(ngram_indices(l, self.dim), dtype=np.int64) for l in labels]
        stats = np.array([_stat_features(l) for l in labels], dtype=np.float32)
        n, d = len(labels), self.dim + N_STAT
        W1, b1 = self.W1.astype(np.float32), self.b1.astype(np.float32)
        W2, b2 = self.W2.astype(np.float32), np.float32(0.0)
        for ep in range(epochs):
            perm = rng.permutation(n)
            correct = 0
            for s in range(0, n, batch):
                bi = perm[s:s + batch]; m = len(bi)
                Xb = np.zeros((m, d), dtype=np.float32)
                for r, i in enumerate(bi):
                    Xb[r, idx_lists[i]] = 1.0
                Xb[:, self.dim:] = stats[bi]
                Hpre = Xb @ W1 + b1                      # (m,H)  BLAS
                Hr = np.maximum(0.0, Hpre)
                z = Hr @ W2 + b2
                p = 1.0 / (1.0 + np.exp(-z))
                g = (p - y[bi]).astype(np.float32)
                correct += int(((p >= 0.5) == (y[bi] >= 0.5)).sum())
                dW2 = Hr.T @ g / m + l2 * W2
                db2 = g.mean()
                dHpre = (np.outer(g, W2) / m) * (Hpre > 0)
                dW1 = Xb.T @ dHpre + l2 * W1             # (d,H)  BLAS
                db1 = dHpre.sum(0)
                W2 -= lr * dW2; b2 = b2 - lr * db2
                W1 -= lr * dW1; b1 -= lr * db1
            if verbose:
                print(f"  epoch {ep+1}/{epochs}  train acc {correct/n:.4f}"); sys.stdout.flush()
        self.W1 = W1.astype(np.float32); self.b1 = b1.astype(np.float32)
        self.W2 = W2.astype(np.float32); self.b2 = float(b2); self.trained = True
        return self

    # ---- persistence ------------------------------------------------------
    def save(self, path: str = _MODEL_PATH):
        # store the large embedding matrix as float16 to keep the committed model
        # small (~7MB); the precision loss is negligible for a summed embedding-bag.
        np.savez_compressed(path, W1=self.W1.astype(np.float16), b1=self.b1, W2=self.W2,
                            b2=np.float32(self.b2), dim=np.int64(self.dim),
                            H=np.int64(self.H), threshold=np.float32(self.threshold))

    @classmethod
    def load(cls, path: str = _MODEL_PATH) -> Optional["DGAModel"]:
        if not os.path.exists(path):
            return None
        d = np.load(path)
        m = cls(dim=int(d["dim"]), hidden=int(d["H"]))
        m.W1 = d["W1"].astype(np.float32); m.b1 = d["b1"].astype(np.float32)
        m.W2 = d["W2"].astype(np.float32); m.b2 = float(d["b2"])
        m.threshold = float(d["threshold"]); m.trained = True
        return m


_CACHE = {}


def load_cached(path: str = _MODEL_PATH) -> Optional["DGAModel"]:
    """Load-once cache so repeated DGAClassifier() instantiations don't re-read disk."""
    if path not in _CACHE:
        _CACHE[path] = DGAModel.load(path)
    return _CACHE[path]


# --------------------------------------------------------------------------- #
# Dataset loading
# --------------------------------------------------------------------------- #
def load_dataset(csv_path: str):
    """chrmor DGA_domains_dataset: 'label,family,domain' per line."""
    rows = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) < 3:
                continue
            label, family, domain = parts[0], parts[1], parts[2]
            rows.append((label, family, domain))
    return rows
