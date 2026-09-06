"""
End-to-end passive pipeline: packets -> half-flows -> detectors -> scored,
evidence-anchored alerts. Deterministic and replayable for forensic use.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple
import hashlib

from .types import Packet, UniFlow, Alert, FLAG_SYN
from .halfflow import HalfFlowReconstructor
from .detectors.beaconing import SpectralBeaconDetector
from .detectors.dga import DGAClassifier
from .detectors.dns_tunnel import DNSTunnelDetector
from .detectors.floods import FloodSlowlorisDetector
from .evidence.ledger import EvidenceLedger, EvidenceBundle

MODEL_ID = "halfsight-ensemble"
MODEL_VERSION = "0.3.1"


def severity_for(conf: float) -> str:
    if conf >= 0.85:
        return "critical"
    if conf >= 0.7:
        return "high"
    if conf >= 0.5:
        return "medium"
    if conf >= 0.3:
        return "low"
    return "info"


class FlowTable:
    """Assembles observed packets into one-directional 5-tuple flows."""

    def __init__(self):
        self.flows: Dict[Tuple, UniFlow] = {}

    def ingest(self, p: Packet) -> UniFlow:
        k = (p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto)
        f = self.flows.get(k)
        if f is None:
            f = UniFlow(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto)
            self.flows[k] = f
        f.update(p)
        return f

    def snapshot(self) -> List[UniFlow]:
        return list(self.flows.values())


class Pipeline:
    def __init__(self, sensor_id: str = "enclave-sensor-01", signing_key: bytes = b"demo-key"):
        self.hf = HalfFlowReconstructor()
        self.beacon = SpectralBeaconDetector()
        self.dga = DGAClassifier()
        self.tunnel = DNSTunnelDetector()
        self.floods = FloodSlowlorisDetector()
        self.ledger = EvidenceLedger(sensor_id, signing_key)

    # ---- helpers -----------------------------------------------------------
    @staticmethod
    def _registrable(qname: str) -> str:
        parts = qname.strip(".").lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else qname

    def _emit(self, alert: Alert, flow: UniFlow, features: dict, now: float) -> Alert:
        pkt_hashes = [hashlib.sha256(f"{flow.key}:{i}".encode()).hexdigest()
                      for i in range(min(flow.packets, 64))]
        bundle = EvidenceBundle(
            alert=alert.to_record(), flow_record={
                "key": flow.key, "packets": flow.packets, "bytes": flow.bytes,
                "duration": round(flow.duration, 3)},
            packet_hashes=pkt_hashes, feature_vector=features,
            model_id=MODEL_ID, model_version=MODEL_VERSION)
        self.ledger.add(bundle, now)
        return alert

    # ---- main --------------------------------------------------------------
    def run_window(self, flows: List[UniFlow], now: float, window_s: float = 30.0) -> List[Alert]:
        alerts: List[Alert] = []

        # 1) volumetric + slow-exhaustion (aggregated per destination)
        for r in self.floods.analyze_window(flows):
            victim_flows = [f for f in flows if f.dst_ip == r.dst_ip]
            fl = victim_flows[0] if victim_flows else flows[0]
            a = Alert(now, "floods", r.threat, severity_for(r.confidence), r.confidence,
                      f"*->{r.dst_ip}", f"{r.threat.replace('_',' ').title()} against {r.dst_ip}",
                      evidence=r.evidence)
            alerts.append(self._emit(a, fl, r.evidence, now))

        # 2) beaconing (per src->dst channel; event = flow start time)
        channels: Dict[Tuple[str, str], List[UniFlow]] = {}
        for f in flows:
            channels.setdefault((f.src_ip, f.dst_ip), []).append(f)
        for (src, dst), fl in channels.items():
            if len(fl) < 8:
                continue
            # Skip known-good periodic services: recursive DNS (53) is covered by
            # the DGA/tunnel path, and NTP/chrony (123/323) are legitimately
            # periodic by design. A production build swaps this for a 2LD/ASN
            # reputation prior; here it is a cheap, honest allowlist.
            benign_periodic = sum(1 for f in fl if f.dst_port in (53, 123, 323))
            if benign_periodic / len(fl) > 0.5:
                continue
            events = sorted(f.start_ts for f in fl)
            sizes = [f.bytes for f in fl]
            br = self.beacon.analyze(events, sizes)
            if br.is_beacon:
                ev = {**br.evidence, "period_s": br.period_s, "jitter_pct": br.jitter_pct}
                a = Alert(now, "beaconing", "c2_beaconing", severity_for(br.confidence),
                          br.confidence, f"{src}->{dst}",
                          f"C2 beacon {src} -> {dst} every ~{br.period_s}s (jitter {br.jitter_pct}%)",
                          evidence=ev)
                alerts.append(self._emit(a, fl[0], ev, now))

        # 3) DNS tunnelling FIRST — its 2LDs are then excluded from DGA scoring
        # (a tunnel's many high-entropy subdomains would otherwise each look DGA-ish).
        # Aggregate qnames/qtypes PER 2LD directly (never per (flow x qname), which
        # would be O(n^2) on a real tunnel capturing tens of thousands of queries).
        by_2ld: Dict[str, dict] = {}
        for f in flows:
            for q, qt in zip(f.dns_qnames, f.dns_qtypes):
                d = self._registrable(q)
                e = by_2ld.get(d)
                if e is None:
                    e = by_2ld[d] = {"qn": [], "qt": [], "uniq": set(), "flow": f}
                e["qn"].append(q); e["qt"].append(qt); e["uniq"].add(q)

        tunnel_domains = set()
        for domain, e in by_2ld.items():
            tr = self.tunnel.analyze(domain, e["qn"], e["qt"], window_s)
            if tr.is_tunnel:
                tunnel_domains.add(domain)
                a = Alert(now, "dns_tunnel", "dns_tunnelling", severity_for(tr.confidence),
                          tr.confidence, f"*->{domain}",
                          f"DNS tunnel over {domain}: ~{tr.uplink_bytes_est} B uplink encoded",
                          evidence=tr.features)
                alerts.append(self._emit(a, e["flow"], tr.features, now))

        # 4) DGA (trained model via BABEL). A DGA rendezvous domain is a DISTINCT
        # 2LD queried ~once; a tunnel is ONE 2LD with many subdomains. So skip DGA
        # scoring on any subdomain-heavy 2LD (detected tunnels + near-threshold
        # tunnel-like domains) — that traffic is the tunnel detector's job.
        skip_dga = set(tunnel_domains) | {d for d, e in by_2ld.items() if len(e["uniq"]) >= 12}

        seen_dga = set()
        for f in flows:
            for q in f.dns_qnames:
                if self._registrable(q) in skip_dga:
                    continue
                d = self.dga.score(q)
                lbl = d.features.get("label", q) or q       # dedup by scored label
                if lbl in seen_dga:
                    continue
                seen_dga.add(lbl)
                if d.is_dga:
                    a = Alert(now, "dga", "dga_domain", severity_for(d.prob_dga), d.prob_dga,
                              f.key, f"DGA domain observed: {q} ({d.family_hint})",
                              evidence=d.features, contributions=d.contributions)
                    alerts.append(self._emit(a, f, d.features, now))

        return alerts

    def seal_and_anchor(self, now: float):
        blk = self.ledger.seal(now)
        if blk:
            self.ledger.anchor(blk.index)
        return blk
