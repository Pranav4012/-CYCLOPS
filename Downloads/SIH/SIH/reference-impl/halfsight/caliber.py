"""
CALIBER — reconstruction-calibrated, distribution-free confidence.

Split-conformal prediction gives every alert a *coverage guarantee* instead of an
opaque score: on exchangeable data, a detector calibrated at level ``alpha`` will
flag a true attack of that class with probability at least ``1 - alpha``. We
calibrate one threshold per threat class (Mondrian conformal), and — this is the
honest part — inflate each nonconformity score by the HalfSight reconstruction
uncertainty, so a verdict that leaned on an imputed half is held to a stricter
bar and its confidence band widens.

The claim "empirical coverage tracks the nominal 1-alpha" is therefore *testable*:
see ``eval/`` for the harness that measures it across alpha and reports the gap.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import math


def _quantile(sorted_vals: List[float], q: float) -> float:
    """Conformal quantile: the ceil((n+1)*q)/n order statistic (clipped)."""
    n = len(sorted_vals)
    if n == 0:
        return 1.0
    k = math.ceil((n + 1) * q)
    k = min(max(k, 1), n)
    return sorted_vals[k - 1]


@dataclass
class ConformalCalibrator:
    """Per-class split-conformal calibrator over detector scores in [0,1]."""
    alpha: float = 0.10
    thresholds: Dict[str, float] = field(default_factory=dict)   # class -> score threshold
    _cal: Dict[str, List[float]] = field(default_factory=dict)

    def fit(self, samples: List[tuple]) -> "ConformalCalibrator":
        """
        samples: list of (threat_class, score, recon_rel_unc) for TRUE positives
        of each class from a held-out calibration split. Nonconformity = how far
        the score falls short of certainty, inflated by reconstruction uncertainty.
        """
        by_cls: Dict[str, List[float]] = {}
        for cls, score, unc in samples:
            nonconf = (1.0 - score) * (1.0 + 0.5 * unc)   # widen when inferred
            by_cls.setdefault(cls, []).append(nonconf)
        for cls, ncs in by_cls.items():
            ncs.sort()
            q = _quantile(ncs, 1.0 - self.alpha)   # covers >= 1-alpha of calibration
            self.thresholds[cls] = max(0.0, 1.0 - q)  # score must clear this to be "covered"
            self._cal[cls] = ncs
        return self

    def covered(self, threat_class: str, score: float, recon_rel_unc: float = 0.0) -> bool:
        thr = self.thresholds.get(threat_class, 1.0 - self.alpha)
        eff = score / (1.0 + 0.5 * recon_rel_unc)     # discount inferred verdicts
        return eff >= thr

    def p_value(self, threat_class: str, score: float, recon_rel_unc: float = 0.0) -> float:
        """Conformal p-value: fraction of calibration nonconformities >= this one."""
        ncs = self._cal.get(threat_class)
        if not ncs:
            return 1.0 - score
        nonconf = (1.0 - score) * (1.0 + 0.5 * recon_rel_unc)
        ge = sum(1 for x in ncs if x >= nonconf)
        return (ge + 1) / (len(ncs) + 1)

    def coverage(self, test_samples: List[tuple]) -> Dict[str, float]:
        """Empirical coverage per class on a test split of true positives."""
        seen: Dict[str, int] = {}
        cov: Dict[str, int] = {}
        for cls, score, unc in test_samples:
            seen[cls] = seen.get(cls, 0) + 1
            if self.covered(cls, score, unc):
                cov[cls] = cov.get(cls, 0) + 1
        return {c: cov.get(c, 0) / seen[c] for c in seen}
