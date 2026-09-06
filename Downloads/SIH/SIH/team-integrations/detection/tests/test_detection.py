from datetime import datetime, timedelta, timezone

import pytest

from halfsight.detectors import babel, floods, spector


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
REQUIRED_ALERT_FIELDS = {"threat_class", "confidence", "severity", "evidence"}


def make_flow(flow_id, timestamp, **fields):
    return {"flow_id": flow_id, "timestamp": timestamp, **fields}


def timestamps(offsets):
    return [(BASE_TIME + timedelta(seconds=offset)).isoformat() for offset in offsets]


def test_spector_alerts_on_regular_beaconing_and_ignores_irregular_traffic():
    regular = timestamps([0, 60, 120, 180, 240, 300])
    irregular = timestamps([0, 10, 100, 110, 200, 210])

    regular_alerts = spector.detect({
        ("10.0.0.1", "10.0.0.2"): [make_flow(str(i), value) for i, value in enumerate(regular)]
    })
    irregular_alerts = spector.detect({
        ("10.0.0.1", "10.0.0.2"): [make_flow(str(i), value) for i, value in enumerate(irregular)]
    })

    assert len(regular_alerts) == 1
    assert irregular_alerts == []


def test_babel_detects_high_entropy_dns_label_but_not_normal_domain():
    common = {
        "timestamp": BASE_TIME.isoformat(),
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
    }
    dga_flow = make_flow(
        "dga", **common, dns_query={"qname": "xj3k9q2m8z7v4p6.com"}
    )
    normal_flow = make_flow(
        "normal", **common, dns_query={"qname": "www.example.com"}
    )

    assert babel.detect([dga_flow])
    assert babel.detect([normal_flow]) == []


def test_babel_detects_high_rate_dns_tunnelling():
    flows = [
        make_flow(
            str(i),
            (BASE_TIME + timedelta(seconds=i)).isoformat(),
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            dns_query={"qname": f"chunk{i:02d}.example.com"},
        )
        for i in range(20)
    ]

    alerts = babel.detect(flows)

    assert len(alerts) == 20
    assert all(alert["threat_class"] == "dga_dns_tunnelling" for alert in alerts)


def test_floods_detects_high_packet_rate_and_reports_source_entropy():
    flows = [
        make_flow(
            str(i),
            BASE_TIME.isoformat(),
            src_ip=f"10.0.0.{i + 1}",
            packet_count=500,
            byte_count=1000,
        )
        for i in range(5)
    ]

    alerts = floods.detect({"10.0.0.2": flows})

    assert len(alerts) == 1
    assert alerts[0]["threat_class"] == "volumetric_ddos"
    assert alerts[0]["evidence"]["distinct_sources"] == 5


def test_floods_ignores_normal_traffic_and_rejects_invalid_window():
    flows = [
        make_flow(
            str(i),
            BASE_TIME.isoformat(),
            src_ip="10.0.0.1",
            packet_count=10,
            byte_count=100,
        )
        for i in range(5)
    ]

    assert floods.detect({"10.0.0.2": flows}) == []
    with pytest.raises(ValueError, match="window_seconds"):
        floods.detect({"10.0.0.2": flows}, window_seconds=0)


def test_alerts_include_shared_contract_fields():
    beacon_flows = [
        make_flow(str(i), value)
        for i, value in enumerate(timestamps([0, 60, 120, 180]))
    ]
    alert = spector.detect({("10.0.0.1", "10.0.0.2"): beacon_flows})[0]

    assert REQUIRED_ALERT_FIELDS <= alert.keys()
    assert 0 <= alert["confidence"] <= 1
    assert alert["severity"] in {"medium", "high", "critical"}
