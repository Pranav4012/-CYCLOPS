#!/usr/bin/env python3
"""
Validate CYCLOPS on REAL, public attack captures — one per threat class.

Every threat in PS 26145 is covered by a genuinely-real .pcap (not synthetic):
downloaded DDoS / DNS-tunnel / Slowloris / Cobalt-Strike-C2 captures from public
research repositories. This runs the real ingestion pipeline on each and checks
that the expected threat is detected.

    ./pcaps/real/fetch_real_captures.sh     # pull the captures (public sources)
    python3 -m eval.validate_real

Writes eval/results/real_pcap_validation.json.
"""
from __future__ import annotations

import json
import os

from halfsight.ingest import run

REAL = os.path.join(os.path.dirname(__file__), "..", "pcaps", "real")
OUT = os.path.join(os.path.dirname(__file__), "results")

# (file, expected threat classes, source, note)
CASES = [
    ("pkt.TCP.synflood.spoofed.pcap", {"syn_flood"},
     "StopDDoS/packet-captures", "real spoofed SYN flood"),
    ("amp.TCP.reflection.SYNACK.pcap", {"reflection_amplification"},
     "StopDDoS/packet-captures", "real TCP SYN-ACK reflection"),
    ("amp.UDP.isakmp.pcap", {"reflection_amplification"},
     "StopDDoS/packet-captures", "real IPsec/ISAKMP amplification"),
    ("amp.UDP.DNSANY.pcap", {"reflection_amplification"},
     "StopDDoS/packet-captures", "real DNS ANY amplification"),
    ("iodine-cname.pcap", {"dns_tunnelling"},
     "ggyggy666/DNS-Tunnel-Datasets", "real iodine DNS tunnel"),
    ("dnscat2-txt.pcap", {"dns_tunnelling"},
     "ggyggy666/DNS-Tunnel-Datasets", "real dnscat2 DNS tunnel (C2)"),
    ("http_slowloris.pcap", {"slowloris"},
     "abastin99/PCAP_files", "real Slowloris slow-HTTP"),
    ("cobaltstrike-hancitor.pcap", {"c2_beaconing", "dga_domain"},
     "malware-traffic-analysis.net", "real Cobalt Strike C2 beacon + DGA"),
]


def main():
    print("=" * 82)
    print("  CYCLOPS · validation on REAL attack captures (public sources)")
    print("=" * 82)
    rows, n_present, n_pass = [], 0, 0
    for fname, expected, source, note in CASES:
        path = os.path.join(REAL, fname)
        if not os.path.exists(path):
            print(f"  [skip] {fname:40} (not fetched — run pcaps/real/fetch_real_captures.sh)")
            rows.append({"file": fname, "status": "missing", "source": source})
            continue
        n_present += 1
        r = run(path, window_s=max(60.0, 0))
        detected = {a.threat for a in r["alerts"]}
        hit = bool(expected & detected)
        n_pass += hit
        top = max(r["alerts"], key=lambda a: a.confidence, default=None)
        mark = "✓" if hit else "✗"
        exp = "/".join(sorted(expected))
        det = ", ".join(f"{a.threat}({a.confidence:.2f})"
                        for a in sorted(r["alerts"], key=lambda a: -a.confidence)[:3]) or "none"
        print(f"  [{mark}] {fname:40} exp {exp:24} -> {det}")
        print(f"        {note} · {r['packets']} pkts / {r['span_s']}s · src: {source}")
        rows.append({"file": fname, "expected": sorted(expected), "detected": sorted(detected),
                     "pass": hit, "packets": r["packets"], "span_s": r["span_s"],
                     "source": source, "note": note,
                     "top": (top.to_record() if top else None)})
    print("-" * 82)
    print(f"  REAL-DATA VALIDATION: {n_pass}/{n_present} captures detected "
          f"({len(CASES)} threat cases across all classes in PS 26145)")
    print("=" * 82)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "real_pcap_validation.json"), "w") as f:
        json.dump({"present": n_present, "passed": n_pass, "cases": rows}, f, indent=2)
    return rows


if __name__ == "__main__":
    main()
