from __future__ import annotations

import math
from collections import Counter

PACKET_RATE_THRESHOLD = 2000.0     # packets/sec toward one dest -> suspicious
BYTE_RATE_THRESHOLD = 500_000.0    # bytes/sec toward one dest -> suspicious
MIN_FLOWS_FOR_JUDGEMENT = 5        # don't judge floods off a handful of flows


def normalized_src_ip_entropy(src_ips: list[str]) -> float:
    """
    Returns 0-1. High entropy = source IPs are evenly spread (many
    distinct IPs, each seen about as often as the others) — a hallmark
    of spoofed-source or botnet floods. Low entropy = traffic dominated
    by a few sources, which looks more like legitimate concentrated load.
    """
    if not src_ips:
        return 0.0
    counts = Counter(src_ips)
    total = len(src_ips)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1.0
    return round(entropy / max_entropy, 3) if max_entropy > 0 else 0.0


def detect(flows_by_dest: dict[str, list[dict]], window_seconds: float = 1.0) -> list[dict]:
    """
    flows_by_dest: {dst_ip: [flow, flow, ...]} within a single time window.
    window_seconds: length of that window, used to convert flow counts
        into rates.
    Returns Alert dicts for destinations under apparent flood conditions.
    """
    alerts = []
    for dst_ip, flows in flows_by_dest.items():
        if len(flows) < MIN_FLOWS_FOR_JUDGEMENT:
            continue

        total_packets = sum(f.get("packet_count", 0) for f in flows)
        total_bytes = sum(f.get("byte_count", 0) for f in flows)
        packet_rate = total_packets / window_seconds
        byte_rate = total_bytes / window_seconds

        src_ips = [f["src_ip"] for f in flows]
        src_entropy = normalized_src_ip_entropy(src_ips)

        is_rate_flood = packet_rate >= PACKET_RATE_THRESHOLD or byte_rate >= BYTE_RATE_THRESHOLD
        if not is_rate_flood:
            continue

        # confidence rises with how far over threshold we are, and with spoof-like entropy
        rate_ratio = max(packet_rate / PACKET_RATE_THRESHOLD, byte_rate / BYTE_RATE_THRESHOLD)
        confidence = min(1.0, 0.5 * min(rate_ratio, 2.0) / 2.0 + 0.5 * src_entropy)

        # attribute to the source contributing the most traffic, not just
        # the most frequent one — avoids arbitrary tie-breaks when many
        # sources each appear once, which is itself a spoofing signal
        packets_by_src: dict[str, int] = {}
        for f in flows:
            packets_by_src[f["src_ip"]] = packets_by_src.get(f["src_ip"], 0) + f.get("packet_count", 0)
        top_src_ip = max(packets_by_src, key=packets_by_src.get)

        alerts.append({
            "timestamp": flows[-1]["timestamp"],
            "flow_id": flows[-1]["flow_id"],
            "threat_class": "volumetric_ddos",
            "confidence": round(confidence, 3),
            "severity": "critical" if confidence > 0.85 else "high",
            "src_ip": top_src_ip,
            "dst_ip": dst_ip,
            "evidence": {
                "packet_rate": round(packet_rate, 1),
                "byte_rate": round(byte_rate, 1),
                "src_ip_entropy": src_entropy,
                "distinct_sources": len(set(src_ips)),
                "flow_count": len(flows),
            },
            "detector": "floods:rate_entropy_v1",
        })
    return alerts