"""
Spectral C2-beaconing detector.

Malware beacons "phone home" on a hidden clock. Naive interval-threshold
detectors die the moment the operator adds jitter (e.g. Cobalt Strike's
``jitter 37``) or a long sleep. We instead treat each src->dst channel as a
*point process* and look for a hidden period in the frequency domain, which
survives heavy jitter because it integrates evidence across many beacons.

Three orthogonal signals, fused:

  1. Rayleigh periodogram over event times (phase coherence).
     For a candidate period P, fold arrivals into phase and measure the
     resultant vector length R. A true beacon concentrates in phase (R -> 1)
     even when individual intervals are jittered. Significance uses the
     Rayleigh false-alarm probability  FAP ~= exp(-N * R^2).
     This is the direction-agnostic analogue of a Lomb-Scargle periodogram,
     appropriate for unevenly sampled *events* rather than sampled values.

  2. Interval regularity (robust CV via MAD) — cheap corroboration.

  3. Payload-size regularity — beacons tend to send near-constant-size check-ins.

Everything is passive and one-directional: we only need the timestamps and
sizes of the direction we can see.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import math

import numpy as np


@dataclass
class BeaconResult:
    is_beacon: bool
    period_s: Optional[float]
    score: float               # [0,1]
    confidence: float          # calibrated [0,1]
    jitter_pct: Optional[float]
    n_events: int
    evidence: dict


class SpectralBeaconDetector:
    def __init__(self, min_events: int = 8, pmin: float = 0.5, pmax: float = 3600.0,
                 n_periods: int = 4000, score_threshold: float = 0.62,
                 max_fap: float = 1e-2, min_cycles: float = 4.0):
        self.min_events = min_events
        self.pmin = pmin
        self.pmax = pmax
        self.n_periods = n_periods
        self.score_threshold = score_threshold
        self.max_fap = max_fap          # look-elsewhere-corrected FAP ceiling
        self.min_cycles = min_cycles    # must observe several beacon cycles

    # ---- component signals -------------------------------------------------
    @staticmethod
    def _robust_cv(intervals: np.ndarray) -> float:
        med = np.median(intervals)
        if med <= 0:
            return 1.0
        mad = np.median(np.abs(intervals - med)) * 1.4826  # ~sigma for normal
        return float(mad / med)

    def rayleigh_scan(self, ts: np.ndarray):
        """Return (best_period, best_R, global_fap) over a log-spaced period grid.

        The single-period Rayleigh FAP is exp(-N*R^2), but we scan a whole grid,
        so the max R is inflated by the *look-elsewhere effect*. We correct with
        the number of statistically INDEPENDENT frequencies in the scanned band,
        M_eff ~= (1/pmin - 1/pmax) * span, giving a Bonferroni-style global FAP.
        Without this a handful of aperiodic events fake a beacon ~90% of the time.
        """
        t = ts - ts[0]
        span = t[-1]
        if span <= 0:
            return None, 0.0, 1.0
        pmax = min(self.pmax, span / 2.0)          # need >= 2 cycles
        pmin = max(self.pmin, span / len(t) / 4.0)  # below mean interval is noise
        if pmax <= pmin:
            return None, 0.0, 1.0
        periods = np.geomspace(pmin, pmax, self.n_periods)
        n = len(t)
        best_R, best_P = 0.0, None
        for P in periods:
            phase = 2.0 * math.pi * (t / P)
            C = np.cos(phase).sum()
            S = np.sin(phase).sum()
            R = math.sqrt(C * C + S * S) / n
            if R > best_R:
                best_R, best_P = R, float(P)
        m_eff = max(1.0, (1.0 / pmin - 1.0 / pmax) * span)   # independent frequencies
        single_fap = math.exp(-n * best_R * best_R)
        global_fap = min(1.0, m_eff * single_fap)            # look-elsewhere corrected
        return best_P, best_R, global_fap

    # ---- top-level ---------------------------------------------------------
    def analyze(self, arrival_ts: List[float], payload_sizes: Optional[List[int]] = None) -> BeaconResult:
        ts = np.array(sorted(arrival_ts), dtype=float)
        n = len(ts)
        if n < self.min_events:
            return BeaconResult(False, None, 0.0, 0.0, None, n,
                                {"reason": f"too few events ({n} < {self.min_events})"})

        intervals = np.diff(ts)
        intervals = intervals[intervals > 0]
        cv = self._robust_cv(intervals) if len(intervals) else 1.0
        regularity = max(0.0, 1.0 - min(1.0, cv))       # 1 == perfectly periodic

        period, R, fap = self.rayleigh_scan(ts)   # fap is look-elsewhere corrected
        coherence = max(0.0, min(1.0, R))
        signif = max(0.0, min(1.0, 1.0 - fap))

        size_reg = 0.5
        if payload_sizes and len(payload_sizes) >= self.min_events:
            sz = np.array(payload_sizes, dtype=float)
            m = sz.mean()
            if m > 0:
                size_cv = float(sz.std() / m)
                size_reg = max(0.0, 1.0 - min(1.0, size_cv))

        # Fuse. Coherence + significance are the backbone; regularity and size
        # regularity refine it. Weighted so a jittered-but-coherent beacon still
        # scores high while a bursty scan (high count, no period) does not.
        score = (0.42 * coherence + 0.28 * signif + 0.18 * regularity + 0.12 * size_reg)
        jitter = round(cv * 100.0, 1) if period else None
        cycles = (ts[-1] - ts[0]) / period if period else 0.0

        # A real beacon must clear the corrected FAP AND have been observed over
        # several cycles — otherwise a few aperiodic events fake a period.
        is_beacon = (period is not None and fap < self.max_fap
                     and cycles >= self.min_cycles and score >= self.score_threshold)
        conf = score * min(1.0, cycles / 8.0) if is_beacon else score * 0.4

        return BeaconResult(
            is_beacon=is_beacon,
            period_s=round(period, 3) if period else None,
            score=round(score, 4),
            confidence=round(conf, 4),
            jitter_pct=jitter,
            n_events=n,
            evidence={
                "rayleigh_R": round(R, 4),
                "false_alarm_prob": f"{fap:.2e}",
                "interval_regularity": round(regularity, 4),
                "size_regularity": round(size_reg, 4),
                "cycles_observed": round(cycles, 1),
                "median_interval_s": round(float(np.median(intervals)), 3) if len(intervals) else None,
            },
        )
