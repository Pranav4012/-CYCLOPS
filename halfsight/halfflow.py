"""
Half-Flow Reconstruction  —  the flagship "unidirectional-first" core.

Every classic flow feature that a bidirectional IDS leans on (RTT from a round
trip, request/response byte ratio, handshake completion, flow completeness) is
UNAVAILABLE when you only see one direction of a link. Instead of retraining a
bidirectional model on halved data, we treat the *unseen return direction* as a
latent variable and estimate a posterior over it. Those estimates then become
shared features for every downstream detector.

Three signals are recovered without ever touching the return path:

  1. TCP-timestamp clock recovery  -> host liveness + spoofing tell.
     A real host's TSval increments at a fixed HZ; fitting ts->TSval recovers
     that clock and its consistency (R^2). Spoofed flood sources show absent or
     incoherent TSval progression across "different" source IPs.

  2. Passive RTT / RTO proxy from retransmission spacing.
     We never see the ACK, but a segment that repeats after a gap reveals the
     sender's retransmission timeout, which tracks smoothed RTT.

  3. Return-half posterior — expected bytes/packets of the direction we cannot
     see, with an uncertainty band, conditioned on the inferred role and a
     protocol prior. Large deviation from the posterior = asymmetric-attack tell
     (e.g. a "connection" that sends data but could never have been answered).

This module is deliberately dependency-light (pure-python linear algebra) so it
runs anywhere in the enclave, including on constrained sensors.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, List
import statistics

from .types import UniFlow

# Common ephemeral-port floor; ports below this are usually the *server* side.
WELLKNOWN_MAX = 1024

# Per-protocol prior on return:observed byte ratio (mean, stdev). Rough,
# deployment-tunable priors distilled from typical enclave traffic. The point is
# not the exact numbers but that the model carries calibrated uncertainty.
RETURN_RATIO_PRIOR = {
    ("TCP", "client"): (6.0, 5.0),   # a client request usually pulls back much more
    ("TCP", "server"): (0.18, 0.15),
    ("UDP", "client"): (2.5, 3.0),
    ("UDP", "server"): (0.5, 0.6),
    ("TCP", "unknown"): (1.0, 2.0),
    ("UDP", "unknown"): (1.0, 2.0),
}


def _unwrap32(vals: List[int]) -> List[int]:
    """Undo 32-bit wraparound in a monotone-increasing counter (TCP TSval / seq)."""
    out = [vals[0]]
    off = 0
    for i in range(1, len(vals)):
        if vals[i] + off < out[-1] - 0x40000000:   # a big backwards jump == a wrap past 2^32
            off += 1 << 32
        out.append(vals[i] + off)
    return out


def _linfit(xs: List[float], ys: List[float]) -> Tuple[float, float, float]:
    """Least-squares slope, intercept, R^2 (pure python)."""
    n = len(xs)
    if n < 3:
        return 0.0, 0.0, 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0:
        return 0.0, my, 0.0
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    return slope, intercept, r2


@dataclass
class HalfFlowEstimate:
    role: str                       # 'client' | 'server' | 'unknown' (observed side)
    ts_clock_hz: Optional[float]    # recovered TCP timestamp clock (Hz)
    ts_clock_r2: float              # fit quality in [0,1] (liveness/coherence)
    passive_rtt_ms: Optional[float] # RTO-proxy RTT estimate
    half_open_ratio: float          # SYNs with no data/teardown, [0,1]
    expected_return_bytes: float    # posterior mean of the unseen direction
    return_band: Tuple[float, float]  # +/-1 sigma band on expected return bytes
    asymmetry_z: float              # how anomalous the (missing) return looks
    liveness_score: float           # [0,1]; low => likely spoofed/synthetic source
    recon_method: str = "prior"     # 'ack-derivative' (measured) | 'prior' (inferred)
    recon_rel_unc: float = 1.0      # relative uncertainty on the reconstruction

    def as_features(self) -> dict:
        return {
            "hf_role": self.role,
            "hf_ts_clock_hz": self.ts_clock_hz,
            "hf_ts_clock_r2": round(self.ts_clock_r2, 4),
            "hf_passive_rtt_ms": self.passive_rtt_ms,
            "hf_half_open_ratio": round(self.half_open_ratio, 4),
            "hf_expected_return_bytes": round(self.expected_return_bytes, 1),
            "hf_recon_method": self.recon_method,
            "hf_asymmetry_z": round(self.asymmetry_z, 3),
            "hf_liveness": round(self.liveness_score, 4),
        }


class HalfFlowReconstructor:
    """Estimate latent return-direction properties from one observed direction."""

    def infer_role(self, flow: UniFlow) -> str:
        # SYN-ACK observed => we're watching the server->client side.
        if flow.synack > 0 and flow.syn == 0:
            return "server"
        # Pure SYNs to a well-known port => client->server side.
        if flow.dst_port <= WELLKNOWN_MAX < flow.src_port:
            return "client"
        if flow.src_port <= WELLKNOWN_MAX < flow.dst_port:
            return "server"
        if flow.syn > flow.synack:
            return "client"
        return "unknown"

    def recover_ts_clock(self, flow: UniFlow) -> Tuple[Optional[float], float]:
        """Fit TSval against wall-clock; slope is the clock Hz, R^2 its coherence."""
        if len(flow.tsval_samples) < 4:
            return None, 0.0
        samples = sorted(flow.tsval_samples)                    # order by capture time
        # PAWS-style filter: keep only serially-advancing TSvals, dropping old or
        # reordered segments (which would otherwise wreck the clock fit).
        fts, fv = [samples[0][0]], [samples[0][1] & 0xFFFFFFFF]
        for t, v in samples[1:]:
            v &= 0xFFFFFFFF
            if ((v - fv[-1]) & 0xFFFFFFFF) < 0x80000000:        # not an older TSval
                fts.append(t); fv.append(v)
        if len(fv) < 4:
            return None, 0.0
        unwrapped = _unwrap32(fv)                               # undo 32-bit TSval wrap
        slope, _, r2 = _linfit(fts, [float(v) for v in unwrapped])
        hz = slope if slope > 0 else None
        return hz, max(0.0, r2)

    def passive_rtt(self, flow: UniFlow) -> Optional[float]:
        """RTO-proxy: median spacing between repeated sequence numbers."""
        # We approximate retransmit spacing using the recorded count + timing.
        if flow.retransmits <= 0 or len(flow.arrival_ts) < 3:
            return None
        gaps = [b - a for a, b in zip(flow.arrival_ts, flow.arrival_ts[1:]) if b > a]
        if not gaps:
            return None
        # RTO is bounded below by ~200ms in most stacks; use a robust low quantile.
        gaps.sort()
        q = gaps[max(0, int(0.1 * len(gaps)))]
        return round(min(q, 3.0) * 1000.0, 2)

    def half_open_ratio(self, flow: UniFlow) -> float:
        """Fraction of SYNs that never turned into a real, teardown-completed flow."""
        syns = flow.syn + flow.synack
        if syns == 0:
            return 0.0
        completed = min(syns, flow.fin + flow.rst)
        data_bearing = 1 if flow.psh > 0 or flow.bytes > syns * 100 else 0
        return max(0.0, 1.0 - (completed + data_bearing) / max(1, syns))

    def reconstruct_reverse_bytes(self, flow: UniFlow) -> Tuple[Optional[float], str, float]:
        """
        GHOSTFLOW core: estimate how many bytes the UNSEEN peer sent back.

        The cumulative-ACK field in the direction we observe is a running receipt
        for the peer's bytes, so ``ack_last - ack_first`` is a direct measurement
        of the reverse volume over the observed window — no prior needed. Falls
        back to a protocol/role prior only when ACK progression isn't visible
        (we're watching the responder side, or UDP). Returns (bytes, method, rel_unc).
        """
        if flow.proto == "TCP" and flow.ack_first is not None and flow.ack_last is not None \
                and flow.ack_samples >= 2:
            # wrap-aware total: add 2^32 per counted 32-bit ACK wraparound.
            est = float((flow.ack_last - flow.ack_first) + flow.ack_wraps * (1 << 32))
            if est <= 0:
                return None, "prior", 1.0
            # delayed-ACK / Nagle coarsen the ACK cadence (~2*MSS steps) but not the
            # cumulative total, so this stays an accurate lower bound; uncertainty
            # shrinks with the number of ACK samples seen (and if the flow was cut
            # before the final ACK, we bias low — hence the floor).
            rel_unc = max(0.02, 1.0 / (flow.ack_samples ** 0.5))
            return est, "ack-derivative", rel_unc
        return None, "prior", 1.0

    def return_posterior(self, flow: UniFlow, role: str) -> Tuple[float, Tuple[float, float], float]:
        mean_ratio, std_ratio = RETURN_RATIO_PRIOR.get((flow.proto, role),
                                                        RETURN_RATIO_PRIOR[(flow.proto, "unknown")])
        exp_bytes = flow.bytes * mean_ratio
        lo = flow.bytes * max(0.0, mean_ratio - std_ratio)
        hi = flow.bytes * (mean_ratio + std_ratio)
        # Asymmetry: a data-bearing flow whose posterior return is ~0 (e.g. flood /
        # one-way exfil) is anomalous. Score how many sigmas the *observed*
        # behaviour implies away from a normal request/response exchange.
        if flow.proto == "TCP" and role == "client" and flow.bytes > 0:
            # a client that pushes data but shows no sign the peer could respond
            # (no ACK growth, high half-open) is suspicious.
            no_response_signal = 1.0 - min(1.0, flow.ack / max(1, flow.packets))
            asym_z = no_response_signal * (mean_ratio / max(1e-6, std_ratio))
        else:
            asym_z = 0.0
        return exp_bytes, (lo, hi), asym_z

    def estimate(self, flow: UniFlow) -> HalfFlowEstimate:
        role = self.infer_role(flow)
        hz, r2 = self.recover_ts_clock(flow)
        rtt = self.passive_rtt(flow)
        ho = self.half_open_ratio(flow)
        exp_bytes, band, asym = self.return_posterior(flow, role)

        # Prefer the measured ACK-derivative reconstruction over the prior when
        # we can see ACK progression — this is what makes the estimate accurate.
        recon_est, recon_method, recon_unc = self.reconstruct_reverse_bytes(flow)
        if recon_method == "ack-derivative":
            exp_bytes = recon_est
            band = (recon_est * (1 - recon_unc), recon_est * (1 + recon_unc))

        # Liveness: a coherent timestamp clock is strong evidence of a real,
        # single, live host. Its absence on a high-rate TCP flow suggests a
        # spoofed / synthetic source (SYN-flood generators rarely bother).
        if flow.proto == "TCP":
            if hz is not None and r2 > 0.9:
                liveness = 0.9 + 0.1 * min(1.0, r2)
            elif flow.tsval_samples:
                liveness = 0.5 * r2
            else:
                # no timestamps at all on a TCP flow with SYNs -> low liveness
                liveness = 0.25 if (flow.syn + flow.synack) > 0 else 0.6
        else:
            liveness = 0.6  # UDP has no TS option; neutral prior

        return HalfFlowEstimate(
            role=role, ts_clock_hz=hz, ts_clock_r2=r2, passive_rtt_ms=rtt,
            half_open_ratio=ho, expected_return_bytes=exp_bytes,
            return_band=band, asymmetry_z=asym, liveness_score=max(0.0, min(1.0, liveness)),
            recon_method=recon_method, recon_rel_unc=recon_unc,
        )
