"""
DGA (Domain Generation Algorithm) scoring — a lightweight, training-free
FANCI-style classifier over the query name string.

Detects algorithmically generated C2 rendezvous domains (the kind malware cycles
through until one resolves) using per-name linguistic features. It needs no
resolution result and no return traffic — just the qname a passive DNS parser
lifts from the request, so it is native to the one-directional setting.

Features (all computable from the string alone):
  - Shannon entropy (bits/char): random labels have high entropy.
  - n-gram "englishness": fraction of adjacent bigrams that occur in real text.
  - digit ratio, vowel ratio, longest consonant run, unique-char ratio.
  - dictionary-DGA tell: several concatenated real words (matsnu/suppobox style).

The features feed a hand-calibrated logistic so the module is useful out of the
box; in production you swap the weights for a trained LSTM/CNN char model and
keep this as the cheap, explainable first stage. Each score ships with per-
feature contributions so an analyst sees *why* a domain was flagged.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import math

from ..types import shannon_entropy

# The ~150 most frequent English bigrams. Presence fraction is a cheap, strong
# "does this look like language" signal. A too-small table flags real compound
# words (e.g. windowsupdate) as random, so this list is deliberately generous.
_COMMON_BIGRAMS = set(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng "
    "se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si "
    "om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut "
    "ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa "
    "im mi ai sh up da su ap ay ci ld ry rd os ov um do go ba bi fi oo "
    "ph gh ck ".split()
)

# Tiny high-frequency word list to catch dictionary-DGAs and reduce FPs on
# legit brandable domains.
_COMMON_WORDS = set(
    "the and for you are with this that have from your they will one all "
    "about time work life world play news shop mail cloud data secure "
    "login online store home page group team best free live game photo "
    "video music money market green water light house money power".split()
)

VOWELS = set("aeiou")


@dataclass
class DGAResult:
    label: str
    prob_dga: float             # [0,1]
    is_dga: bool
    family_hint: str            # 'arithmetic/hash' | 'dictionary' | 'benign'
    features: dict
    contributions: dict


class DGAClassifier:
    def __init__(self, threshold: float = 0.5, use_model: bool = True):
        self.threshold = threshold
        # Prefer the trained char-n-gram model (halfsight/dga_model.npz) when it
        # exists; fall back to the hand-tuned logistic below otherwise. The model
        # is trained on real DGA-family data — see eval/train_dga.py.
        self.model = None
        if use_model:
            try:
                from ..dga_model import load_cached
                self.model = load_cached()
            except Exception:
                self.model = None
        # Logistic weights (bias first), calibrated against REAL data — published
        # Cryptolocker DGA domains vs a real benign top-domains list (see
        # halfsight/dga_families.py). The "shape" penalties are length-gated (see
        # score) so short brandable domains (slack, npmjs, nvidia) stop
        # false-firing. Result on real data: ~86% arithmetic-DGA recall at ~2% FPR.
        # Replace with a trained char-LSTM in production; keep this as the cheap
        # first stage. Dictionary DGAs need BABEL's cross-host WordGraph, not this.
        self.w = {
            "bias": -2.6,
            "entropy": 1.4,         # per bit/char above ~3.1
            "non_englishness": 3.8, # fraction of rare bigrams (length-gated)
            "digit_ratio": 3.0,
            "cons_run": 0.4,        # per char over 5 (length-gated)
            "length": 0.2,          # per char over 11
            "low_vowel": 1.0,       # vowel-ratio deficiency (length-gated)
            "dict_words": 1.4,      # concatenated dictionary words (>=3)
        }

    @staticmethod
    def _registrable_label(qname: str) -> str:
        # Take the label just left of the public-ish suffix; good enough for a
        # reference impl (a real deployment uses the PSL).
        q = qname.strip(".").lower()
        parts = q.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else q

    def features(self, qname: str) -> dict:
        label = self._registrable_label(qname)
        n = len(label)
        if n == 0:
            return {"length": 0}
        ent = shannon_entropy(label)
        digits = sum(c.isdigit() for c in label)
        vowels = sum(c in VOWELS for c in label if c.isalpha())
        alpha = sum(c.isalpha() for c in label)
        # longest consonant run
        run = maxrun = 0
        for c in label:
            if c.isalpha() and c not in VOWELS:
                run += 1
                maxrun = max(maxrun, run)
            else:
                run = 0
        bigrams = [label[i:i + 2] for i in range(n - 1) if label[i:i + 2].isalpha()]
        eng = (sum(bg in _COMMON_BIGRAMS for bg in bigrams) / len(bigrams)) if bigrams else 0.0
        # dictionary-DGA: count real words that appear as substrings
        dict_hits = sum(1 for w in _COMMON_WORDS if len(w) >= 4 and w in label)
        return {
            "label": label,
            "length": n,
            "entropy": round(ent, 3),
            "digit_ratio": round(digits / n, 3),
            "vowel_ratio": round((vowels / alpha) if alpha else 0.0, 3),
            "max_cons_run": maxrun,
            "englishness": round(eng, 3),
            "dict_word_hits": dict_hits,
        }

    def score(self, qname: str) -> DGAResult:
        f = self.features(qname)
        if f.get("length", 0) < 5:
            return DGAResult(qname, 0.0, False, "benign", f, {})
        w = self.w
        # Length gate: englishness / vowel / consonant-run signals are only
        # reliable on longer labels — short brandable domains (5-7 chars) have
        # noisy bigram stats and must not be penalised for them.
        Lf = max(0.0, min(1.0, (f["length"] - 8) / 4.0))
        contrib = {
            "entropy": w["entropy"] * max(0.0, f["entropy"] - 3.1),
            "non_englishness": w["non_englishness"] * (1.0 - f["englishness"]) * Lf,
            "digit_ratio": w["digit_ratio"] * f["digit_ratio"],
            "cons_run": w["cons_run"] * max(0, f["max_cons_run"] - 5) * Lf,
            "length": w["length"] * max(0, f["length"] - 11),
            "low_vowel": w["low_vowel"] * max(0.0, 0.30 - f["vowel_ratio"]) * Lf,
            "dict_words": w["dict_words"] * (1 if f["dict_word_hits"] >= 3 else 0),
        }
        z = w["bias"] + sum(contrib.values())
        heur_prob = 1.0 / (1.0 + math.exp(-z))

        # Decision: the trained char-n-gram model when available, else the
        # heuristic. The heuristic's per-feature contributions are kept either way
        # as human-readable evidence for the alert card.
        if self.model is not None:
            prob = self.model.prob(qname)
            is_dga = prob >= self.model.threshold
        else:
            prob = heur_prob
            is_dga = prob >= self.threshold

        if f["dict_word_hits"] >= 3 and f["englishness"] > 0.4:
            family = "dictionary"
        elif is_dga:
            family = "arithmetic/hash"
        else:
            family = "benign"

        # normalize contributions for display (share of positive drive)
        pos = {k: v for k, v in contrib.items() if v > 0}
        tot = sum(pos.values()) or 1.0
        contributions = {k: round(v / tot, 3) for k, v in sorted(pos.items(), key=lambda kv: -kv[1])}

        return DGAResult(qname, round(prob, 4), is_dga, family, f, contributions)
