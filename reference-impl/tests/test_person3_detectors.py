"""Person 3 coverage for the authoritative CYCLOPS detectors."""

from eval import labeled as scenarios
from halfsight import FlowTable
from halfsight.pipeline import Pipeline


def _run(packets, now=100.0):
    table = FlowTable()
    for packet in packets:
        table.ingest(packet)
    return Pipeline().run_window(table.snapshot(), now=now)


def _threats(packets):
    return {alert.threat for alert in _run(packets)}


def test_specter_c2_beaconing_label():
    packets, _ = scenarios.c2_beacon(0.0, "203.0.113.66", "10.0.0.5", 1)

    assert "c2_beaconing" in _threats(packets)


def test_babel_dga_domain_label():
    packets, _ = scenarios.dga_lookups(0.0, "10.0.0.6", 2)

    assert "dga_domain" in _threats(packets)


def test_babel_dns_tunnelling_label():
    packets, _ = scenarios.dns_tunnel(0.0, "tunnel-c2.net", 3)

    assert "dns_tunnelling" in _threats(packets)


def test_floods_syn_flood_label():
    packets, _ = scenarios.syn_flood(0.0, "203.0.113.10", 4)

    assert "syn_flood" in _threats(packets)


def test_floods_reflection_amplification_label():
    packets, _ = scenarios.reflection(0.0, "203.0.115.10", 5)

    assert "reflection_amplification" in _threats(packets)
