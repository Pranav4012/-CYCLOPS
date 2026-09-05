"""FLOODLIGHT + HOURGLASS — SYN/UDP flood, reflection (UDP amp + TCP SYN-ACK),
Slowloris; and benign traffic staying clean."""
from halfsight import FlowTable
from halfsight.types import Packet, FLAG_SYN, FLAG_ACK
from halfsight.detectors.floods import FloodSlowlorisDetector
from eval import labeled as L

det = FloodSlowlorisDetector()


def _threats(pkts):
    ft = FlowTable()
    for p in pkts:
        ft.ingest(p)
    return {r.threat for r in det.analyze_window(ft.snapshot())}


def test_syn_flood():
    assert "syn_flood" in _threats(L.syn_flood(0.0, "203.0.113.10", 1)[0])


def test_udp_flood():
    assert "udp_flood" in _threats(L.udp_flood(0.0, "203.0.114.10", 2)[0])


def test_reflection_amplification():
    assert "reflection_amplification" in _threats(L.reflection(0.0, "203.0.115.10", 3)[0])


def test_tcp_synack_reflection():
    # many reflectors sending SYN-ACK to a spoofed victim (TCP reflection)
    pk = []
    for i in range(80):
        src = f"192.0.2.{i % 250 + 1}"
        for _ in range(30):
            pk.append(Packet(0.001 * i, src, "203.0.113.5", 443, 44000 + i, "TCP", 60,
                             tcp_flags=FLAG_SYN | FLAG_ACK))
    assert "reflection_amplification" in _threats(pk)


def test_slowloris():
    assert "slowloris" in _threats(L.slowloris(0.0, "203.0.116.10", 4)[0])


def test_benign_no_flood():
    assert _threats(L.benign_background(0.0, 5)[0]) == set()
    assert _threats(L.flash_crowd(0.0, "203.0.120.5", 6)[0]) == set()
