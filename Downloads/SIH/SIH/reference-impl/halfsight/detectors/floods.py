"""
Volumetric-DoS and slow-exhaustion detection from one-directional flow.

Covers four related threats a diode can see without the return path:

  * SYN flood — a storm of SYNs to a victim that never complete. Because we
    never see the SYN-ACK, we lean on half-open ratio, source-IP spread
    (spoofing entropy) and the half-flow *liveness* score (spoofed sources have
    no coherent TCP-timestamp clock).
  * UDP flood — high packet/byte rate to a victim from many sources with
    near-uniform tiny payloads.
  * Reflection/amplification — the observed side is the *reflected* traffic:
    large UDP responses from classic amplifiers (DNS/NTP/memcached/SSDP source
    ports) converging on one victim.
  * Slowloris / slow-HTTP — the opposite of volumetric: a few dozen long-lived,
    low-byte-rate, partial-header connections holding a web server's pool open.

Detection aggregates per destination inside a sliding window. Source-IP entropy
is the spoofing tell; the half-flow liveness signal is what lets us separate a
real flash crowd (live hosts, coherent clocks) from a spoofed flood.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict
from collections import Counter
import math

from ..types import UniFlow
from ..halfflow import HalfFlowReconstructor

_AMPLIFIER_PORTS = {
    53: "DNS", 123: "NTP", 11211: "memcached", 1900: "SSDP", 389: "CLDAP",
    500: "ISAKMP", 4500: "IPsec-NAT-T", 19: "chargen", 17: "QOTD", 520: "RIP", 161: "SNMP",
    111: "Portmap", 3702: "WS-Discovery", 5683: "CoAP", 137: "NetBIOS",
    27015: "SrcDS", 69: "TFTP", 5060: "SIP", 37810: "DVR/IoT", 10001: "Ubiquiti",
}


@dataclass
class FloodResult:
    dst_ip: str
    threat: str                 # 'syn_flood'|'udp_flood'|'reflection_amplification'|'slowloris'|'benign'
    score: float
    confidence: float
    evidence: dict = field(default_factory=dict)


def _ip_entropy(ips: List[str]) -> float:
    """Normalized Shannon entropy of the source-IP distribution, [0,1]."""
    if not ips:
        return 0.0
    counts: Dict[str, int] = {}
    for ip in ips:
        counts[ip] = counts.get(ip, 0) + 1
    n = len(ips)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    u = len(counts)
    return h / math.log2(u) if u > 1 else 0.0


class FloodSlowlorisDetector:
    def __init__(self, window_s: float = 10.0,
                 syn_rate_thr: float = 40.0, udp_pps_thr: float = 500.0,
                 slowloris_min_conns: int = 20):
        self.window_s = window_s
        self.syn_rate_thr = syn_rate_thr
        self.udp_pps_thr = udp_pps_thr
        self.slowloris_min_conns = slowloris_min_conns
        self.hf = HalfFlowReconstructor()

    def analyze_window(self, flows: List[UniFlow]) -> List[FloodResult]:
        by_dst: Dict[str, List[UniFlow]] = {}
        for f in flows:
            by_dst.setdefault(f.dst_ip, []).append(f)

        results = []
        for dst, fl in by_dst.items():
            results.extend(self._score_dst(dst, fl))
        return [r for r in results if r.threat != "benign"]

    def _score_dst(self, dst: str, flows: List[UniFlow]) -> List[FloodResult]:
        out = []
        # Rate over the ACTUAL observed span for THIS destination, not a fixed
        # window — so real captures (often sub-second bursts) and long ones both
        # yield correct pps/rate. Floor avoids divide-by-tiny.
        starts = [f.start_ts for f in flows]; lasts = [f.last_ts for f in flows]
        span = (max(lasts) - min(starts)) if starts else 0.0
        w = max(0.5, span)
        srcs = [f.src_ip for f in flows]
        src_entropy = _ip_entropy(srcs)
        n_src = len(set(srcs))

        # ---- SYN flood -----------------------------------------------------
        syn_flows = [f for f in flows if f.proto == "TCP" and (f.syn + f.synack) > 0]
        total_syn = sum(f.syn for f in syn_flows)
        if total_syn > 0:
            syn_rate = total_syn / w
            liveness = [self.hf.estimate(f).liveness_score for f in syn_flows]
            mean_live = sum(liveness) / len(liveness) if liveness else 0.5
            half_open = sum(self.hf.half_open_ratio(f) for f in syn_flows) / len(syn_flows)
            drive = (min(1.0, syn_rate / self.syn_rate_thr) * 0.4
                     + half_open * 0.25 + src_entropy * 0.2 + (1.0 - mean_live) * 0.15)
            if syn_rate >= self.syn_rate_thr and half_open > 0.6:
                out.append(FloodResult(dst, "syn_flood", round(min(1.0, drive), 4),
                    round(min(1.0, drive) * (0.7 + 0.3 * (1 - mean_live)), 4),
                    {"syn_rate_hz": round(syn_rate, 1), "unique_sources": n_src,
                     "src_ip_entropy": round(src_entropy, 3), "half_open_ratio": round(half_open, 3),
                     "mean_liveness": round(mean_live, 3),
                     "note": "low liveness + high src entropy => spoofed sources"}))

        # ---- TCP SYN-ACK reflection (reflectors answer a spoofed victim's SYNs) --
        total_synack = sum(f.synack for f in flows if f.proto == "TCP")
        total_syn_all = sum(f.syn for f in flows if f.proto == "TCP")
        if total_synack > 0:
            synack_rate = total_synack / w
            # a victim's ingress full of SYN-ACKs from many sources it never SYNed
            # to is reflected backscatter — the TCP analogue of UDP amplification.
            if synack_rate >= self.syn_rate_thr and n_src >= 20 and total_synack > total_syn_all:
                drive = min(1.0, synack_rate / (self.syn_rate_thr * 4)) * 0.5 + src_entropy * 0.5
                out.append(FloodResult(dst, "reflection_amplification",
                    round(min(1.0, max(0.6, drive)), 4), round(min(1.0, max(0.55, drive * 0.9)), 4),
                    {"amplifier": "TCP SYN-ACK", "synack_rate_hz": round(synack_rate, 1),
                     "reflector_sources": n_src, "src_ip_entropy": round(src_entropy, 3),
                     "note": "reflected SYN-ACK backscatter from spoofed SYNs"}))

        # ---- UDP flood / reflection ---------------------------------------
        udp_flows = [f for f in flows if f.proto == "UDP"]
        if udp_flows:
            pkts = sum(f.packets for f in udp_flows)
            pps = pkts / w
            byte_rate = sum(f.bytes for f in udp_flows) / w
            # reflection: a MAJORITY of packets arrive FROM amplifier service ports
            # with a large average response — aggregate over the port, not per-flow
            # (a real DNS-ANY flood is many 1-packet reflector flows).
            amp_flows = [f for f in udp_flows if f.src_port in _AMPLIFIER_PORTS]
            amp_pkts = sum(f.packets for f in amp_flows)
            amp_bytes = sum(f.bytes for f in amp_flows)
            amp_avg = amp_bytes / max(1, amp_pkts)
            n_reflectors = len(set(f.src_ip for f in amp_flows))
            # true reflection = a MAJORITY of packets from amplifier ports, large
            # average response, HIGH rate, and MANY distinct reflectors. Without the
            # rate + reflector-count guards a normal client<->resolver DNS chat (or a
            # low-rate DNS tunnel) would false-fire as amplification.
            if (amp_pkts / max(1, pkts) > 0.5 and amp_avg > 180
                    and byte_rate >= 100_000 and n_reflectors >= 10):
                svc_port = Counter(f.src_port for f in amp_flows).most_common(1)[0][0]
                svc = _AMPLIFIER_PORTS.get(svc_port, "UDP")
                drive = min(1.0, byte_rate / (self.udp_pps_thr * 300))
                out.append(FloodResult(dst, "reflection_amplification",
                    round(max(0.6, drive), 4), round(max(0.55, drive * 0.9), 4),
                    {"amplifier": svc, "byte_rate_bps": int(byte_rate),
                     "reflector_sources": len(set(f.src_ip for f in amp_flows)),
                     "mean_response_size": round(amp_avg, 1)}))
            elif pps >= self.udp_pps_thr:
                drive = min(1.0, pps / self.udp_pps_thr / 2) * 0.6 + src_entropy * 0.4
                out.append(FloodResult(dst, "udp_flood", round(min(1.0, drive), 4),
                    round(min(1.0, drive) * 0.85, 4),
                    {"pps": round(pps, 1), "unique_sources": n_src,
                     "src_ip_entropy": round(src_entropy, 3)}))

        # ---- Slowloris -----------------------------------------------------
        web = [f for f in flows if f.dst_port in (80, 443, 8080, 8443) and f.proto == "TCP"]
        slow = [f for f in web
                if f.duration > 8.0 and f.byte_rate < 40.0 and
                (f.http_partial_count > 0 or (f.packets > 3 and f.mean_pkt_size < 80))]
        if len(slow) >= self.slowloris_min_conns:
            mean_dur = sum(f.duration for f in slow) / len(slow)
            drive = min(1.0, len(slow) / (self.slowloris_min_conns * 2)) * 0.6 + min(1.0, mean_dur / 60) * 0.4
            out.append(FloodResult(dst, "slowloris", round(min(1.0, drive), 4),
                round(min(1.0, drive) * 0.9, 4),
                {"concurrent_slow_conns": len(slow), "mean_duration_s": round(mean_dur, 1),
                 "mean_byte_rate_bps": round(sum(f.byte_rate for f in slow) / len(slow), 1),
                 "partial_http_flows": sum(1 for f in slow if f.http_partial_count > 0)}))
        return out
