"""
DNS tunnelling detector (dnscat2 / iodine style).

Tunnels smuggle a data channel inside DNS by encoding payload into subdomain
labels and pulling responses down via TXT/NULL/CNAME records. Passively, and in
one direction, the *uplink* (client -> resolver) is enough to see it: a single
registrable domain suddenly sources a torrent of long, high-entropy, almost
always-unique subdomains, often with exotic qtypes.

We aggregate per registrable domain rather than per packet, because the tell is
statistical across many queries. This is what separates a tunnel from a busy CDN
(which reuses a small set of hostnames) or an anti-spam RBL lookup (short,
structured labels).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List
import math

from ..types import shannon_entropy

_EXOTIC_QTYPES = {"TXT", "NULL", "CNAME", "MX", "AAAA?"}  # data-carrying friendly


@dataclass
class DNSTunnelResult:
    domain: str
    is_tunnel: bool
    score: float
    confidence: float
    uplink_bytes_est: int
    features: dict


class DNSTunnelDetector:
    def __init__(self, threshold: float = 0.6, min_queries: int = 15):
        self.threshold = threshold
        self.min_queries = min_queries

    @staticmethod
    def _subdomain(qname: str, domain: str) -> str:
        q = qname.strip(".").lower()
        if q.endswith(domain):
            return q[: -len(domain)].strip(".")
        return ".".join(q.split(".")[:-2])

    def analyze(self, domain: str, qnames: List[str], qtypes: List[str],
                window_s: float) -> DNSTunnelResult:
        n = len(qnames)
        if n < self.min_queries:
            return DNSTunnelResult(domain, False, 0.0, 0.0, 0,
                                   {"reason": f"too few queries ({n})"})

        subs = [self._subdomain(q, domain) for q in qnames]
        subs = [s for s in subs if s]
        lengths = [len(s) for s in subs] or [0]
        entropies = [shannon_entropy(s) for s in subs] or [0.0]
        unique_ratio = len(set(subs)) / len(subs) if subs else 0.0
        mean_len = sum(lengths) / len(lengths)
        mean_ent = sum(entropies) / len(entropies)
        exotic = sum(1 for t in qtypes if t.upper() in _EXOTIC_QTYPES) / max(1, len(qtypes))
        rate = n / window_s if window_s > 0 else 0.0
        uplink_bytes = int(sum(lengths) * 0.6)  # base32/64 labels carry ~0.6 B/char

        # feature -> [0,1] activations. Calibrated against REAL tunnels (iodine /
        # dnscat2) which — unlike a naive synthetic tunnel — reuse subdomains (so
        # unique-ratio ~0.5, not ~1.0) but hammer ONE 2LD tens of thousands of
        # times. Sheer query volume to a single 2LD is therefore a first-class tell.
        f_len = min(1.0, mean_len / 40.0)         # tunnels use long labels
        f_ent = min(1.0, max(0.0, (mean_ent - 2.8) / 1.5))
        f_uniq = min(1.0, unique_ratio / 0.6)     # ~0.5 unique is already very high
        f_exotic = exotic
        f_rate = min(1.0, rate / 20.0)
        f_vol = min(1.0, n / 300.0)               # query volume to a single 2LD

        score = (0.20 * f_len + 0.12 * f_ent + 0.24 * f_uniq +
                 0.18 * f_exotic + 0.10 * f_rate + 0.16 * f_vol)
        is_tunnel = score >= self.threshold and mean_len > 15 and n >= self.min_queries
        conf = score if is_tunnel else score * 0.6

        return DNSTunnelResult(
            domain=domain, is_tunnel=is_tunnel, score=round(score, 4),
            confidence=round(conf, 4), uplink_bytes_est=uplink_bytes,
            features={
                "queries": n,
                "mean_subdomain_len": round(mean_len, 1),
                "mean_subdomain_entropy": round(mean_ent, 3),
                "unique_subdomain_ratio": round(unique_ratio, 3),
                "exotic_qtype_ratio": round(exotic, 3),
                "query_rate_hz": round(rate, 2),
                "uplink_bytes_est": uplink_bytes,
            },
        )
