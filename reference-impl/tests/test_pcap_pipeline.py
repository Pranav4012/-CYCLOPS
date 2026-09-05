"""Real pcap read/write round-trip + end-to-end Pipeline (one-shot & streaming)."""
import pytest

from halfsight.types import Packet, FLAG_ACK, FLAG_PSH
from halfsight.pcap import read_pcap, write_pcap
from halfsight import Pipeline, FlowTable
from halfsight.ingest import run, run_streaming
from eval import labeled as L


def _scenario():
    pk = []
    pk += L.benign_background(0.0, 1)[0]
    pk += L.syn_flood(0.0, "203.0.113.10", 2)[0]
    pk += L.slowloris(0.0, "203.0.113.20", 3)[0]
    pk += L.dns_tunnel(0.0, "sync-telemetry.net", 4)[0]
    pk += L.c2_beacon(0.0, "203.0.113.66", "10.0.6.9", 5, period=60, jitter=0.12, n=16)[0]
    return sorted(pk, key=lambda p: p.ts)


def test_pcap_roundtrip_preserves_fields(tmp_path):
    pkts = [
        Packet(1.0, "10.0.0.1", "1.2.3.4", 5000, 443, "TCP", 200,
               tcp_flags=FLAG_ACK | FLAG_PSH, tcp_ack=123456, tcp_tsval=999),
        Packet(1.1, "10.0.0.1", "8.8.8.8", 5001, 53, "UDP", 40,
               dns_qname="abc123.evil.example", dns_qtype="TXT"),
        Packet(1.2, "10.0.0.1", "1.2.3.4", 5002, 80, "TCP", 30,
               tcp_flags=FLAG_ACK | FLAG_PSH, tcp_ack=1, http_partial=True),
    ]
    path = str(tmp_path / "rt.pcap")
    write_pcap(path, pkts)
    back = list(read_pcap(path, backend="pure"))
    assert len(back) == 3
    tcp, dns, http = back
    assert tcp.proto == "TCP" and tcp.tcp_ack == 123456 and tcp.tcp_tsval == 999
    assert dns.dns_qname == "abc123.evil.example" and dns.dns_qtype == "TXT"
    assert http.http_partial is True


def test_read_non_pcap_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"NOTAPCAP" * 8)                    # >=24 bytes, wrong magic
    with pytest.raises(ValueError):
        list(read_pcap(str(bad), backend="pure"))


def test_pipeline_detects_all_threats():
    ft = FlowTable()
    for p in _scenario():
        ft.ingest(p)
    threats = {a.threat for a in Pipeline().run_window(ft.snapshot(), now=2000.0, window_s=30.0)}
    for expected in ("syn_flood", "slowloris", "dns_tunnelling", "c2_beaconing"):
        assert expected in threats


def test_pipeline_benign_clean():
    ft = FlowTable()
    for p in L.benign_background(0.0, 9, n_hosts=20)[0]:
        ft.ingest(p)
    assert Pipeline().run_window(ft.snapshot(), now=2000.0, window_s=30.0) == []


def test_ingest_and_streaming(tmp_path):
    path = str(tmp_path / "scen.pcap")
    write_pcap(path, _scenario())
    one = {a.threat for a in run(path)["alerts"]}
    assert "syn_flood" in one and "dns_tunnelling" in one
    r = run_streaming(path, window_s=300.0)
    assert r["windows"] >= 1
    assert {a.threat for a in r["alerts"]} & {"syn_flood", "slowloris", "dns_tunnelling"}
    assert r["ledger"]["chain_intact"]
