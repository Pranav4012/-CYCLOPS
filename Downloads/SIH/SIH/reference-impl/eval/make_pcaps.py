#!/usr/bin/env python3
"""
Write labeled, real .pcap capture files from the eval generators.

Produces Wireshark-openable classic pcaps under `pcaps/` — one mixed capture
containing benign traffic plus all four threats, and one focused capture per
threat. Then you can run the real ingestion path on them:

    python3 -m eval.make_pcaps
    python3 -m halfsight.ingest pcaps/mixed.pcap

The packet *contents* are lab-synthesized, but the file format, framing and
parsing are 100% real — the exact path a diode capture would take.
"""
from __future__ import annotations

import os

from halfsight.pcap import write_pcap
from eval import labeled as L


def build_mixed():
    pk = []
    pk += L.benign_background(0.0, 1)[0]
    pk += L.flash_crowd(0.0, "203.0.120.5", 2, n_clients=60)[0]
    pk += L.syn_flood(0.0, "203.0.113.10", 3)[0]
    pk += L.slowloris(0.0, "203.0.113.20", 4)[0]
    pk += L.dns_tunnel(0.0, "sync-telemetry.net", 5)[0]
    pk += L.dga_lookups(0.0, "10.0.5.9", 6)[0]
    pk += L.c2_beacon(0.0, "203.0.113.66", "10.0.6.9", 7, period=60, jitter=0.12, n=16)[0]
    return pk


def main():
    out = os.path.join(os.path.dirname(__file__), "..", "pcaps")
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    captures = {
        "mixed": build_mixed(),
        "benign": L.benign_background(0.0, 11, n_hosts=24)[0] + L.flash_crowd(0.0, "203.0.120.9", 12, 80)[0],
        "syn_flood": L.benign_background(0.0, 21)[0] + L.syn_flood(0.0, "203.0.113.10", 22)[0],
        "slowloris": L.benign_background(0.0, 31)[0] + L.slowloris(0.0, "203.0.113.20", 32)[0],
        "dns_tunnel": L.benign_background(0.0, 41)[0] + L.dns_tunnel(0.0, "sync-telemetry.net", 42)[0],
        "dga_beacon": L.benign_background(0.0, 51)[0] + L.dga_lookups(0.0, "10.0.5.9", 52)[0]
                      + L.c2_beacon(0.0, "203.0.113.66", "10.0.6.9", 53, period=60, jitter=0.12, n=16)[0],
    }
    print("writing real pcaps to", out)
    for name, pkts in captures.items():
        pkts = sorted(pkts, key=lambda p: p.ts)
        path = os.path.join(out, name + ".pcap")
        n = write_pcap(path, pkts)
        print(f"  {name+'.pcap':20} {n:5d} packets  {os.path.getsize(path):>8d} bytes")
    print("\ningest with:  python3 -m halfsight.ingest pcaps/mixed.pcap")


if __name__ == "__main__":
    main()
