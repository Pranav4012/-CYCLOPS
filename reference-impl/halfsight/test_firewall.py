import firewall

from firewall import AdaptiveFirewall


def test_import():
    print("[1] Testing correct firewall import...")

    print("Imported firewall from:")
    print(firewall.__file__)

    expected_file = "firewall.py"

    assert firewall.__file__.endswith(expected_file)

    print("Import: PASSED")


def test_threat_classification():
    print("\n[2] Testing threat classification...")

    fw = AdaptiveFirewall()

    assert fw.classify_threat(0.00) == "MINIMAL"
    assert fw.classify_threat(0.09) == "MINIMAL"

    assert fw.classify_threat(0.10) == "LOW"
    assert fw.classify_threat(0.20) == "LOW"
    assert fw.classify_threat(0.29) == "LOW"

    assert fw.classify_threat(0.30) == "MEDIUM"
    assert fw.classify_threat(0.50) == "MEDIUM"
    assert fw.classify_threat(0.59) == "MEDIUM"

    assert fw.classify_threat(0.60) == "HIGH"
    assert fw.classify_threat(0.80) == "HIGH"
    assert fw.classify_threat(0.89) == "HIGH"

    assert fw.classify_threat(0.90) == "CRITICAL"
    assert fw.classify_threat(1.00) == "CRITICAL"

    print("Threat classification: PASSED")


def test_validation():
    print("\n[3] Testing validation...")

    fw = AdaptiveFirewall()

    try:
        fw.classify_threat(-0.1)
        assert False, "Negative threat level should raise ValueError"
    except ValueError:
        pass

    try:
        fw.classify_threat(1.1)
        assert False, "Threat level above 1 should raise ValueError"
    except ValueError:
        pass

    try:
        fw.classify_threat("0.5")
        assert False, "String threat level should raise TypeError"
    except TypeError:
        pass

    print("Validation: PASSED")


def test_allowlist():
    print("\n[4] Testing allowlist...")

    fw = AdaptiveFirewall()

    source = "trusted-source"

    assert fw.add_to_allowlist(source) is True
    assert fw.is_allowlisted(source) is True

    result = fw.evaluate(
        source,
        0.95,
    )

    assert result["allowed"] is True
    assert result["action"] == "ALLOW"

    assert fw.remove_from_allowlist(source) is True
    assert fw.is_allowlisted(source) is False

    print("Allowlist: PASSED")


def test_permanent_block():
    print("\n[5] Testing permanent blocking...")

    fw = AdaptiveFirewall()

    source = "blocked-source"

    assert fw.block(
        source,
        reason="Test block",
        threat_level=0.9,
    ) is True

    assert fw.is_blocked(source) is True

    result = fw.evaluate(
        source,
        0.1,
    )

    assert result["allowed"] is False
    assert result["action"] == "BLOCK"

    assert fw.unblock(source) is True
    assert fw.is_blocked(source) is False

    print("Permanent blocking: PASSED")


def test_temporary_block():
    print("\n[6] Testing temporary blocking...")

    fw = AdaptiveFirewall()

    source = "temporary-source"

    assert fw.temporary_block(
        source,
        duration_seconds=60,
        reason="Test temporary block",
        threat_level=0.7,
    ) is True

    assert fw.has_active_temporary_rule(source) is True
    assert fw.is_blocked(source) is True

    result = fw.evaluate(
        source,
        0.1,
    )

    assert result["allowed"] is False

    assert fw.remove_temporary_rule(source) is True
    assert fw.has_active_temporary_rule(source) is False

    print("Temporary blocking: PASSED")


def test_automatic_actions():
    print("\n[7] Testing automatic threat actions...")

    fw = AdaptiveFirewall()

    minimal = fw.evaluate(
        "minimal-source",
        0.05,
    )

    assert minimal["allowed"] is True
    assert minimal["classification"] == "MINIMAL"

    low = fw.evaluate(
        "low-source",
        0.10,
    )

    assert low["allowed"] is True
    assert low["classification"] == "LOW"

    medium = fw.evaluate(
        "medium-source",
        0.30,
    )

    assert medium["allowed"] is True
    assert medium["classification"] == "MEDIUM"

    high = fw.evaluate(
        "high-source",
        0.70,
    )

    assert high["allowed"] is False
    assert high["classification"] == "HIGH"

    critical = fw.evaluate(
        "critical-source",
        0.95,
    )

    assert critical["allowed"] is False
    assert critical["classification"] == "CRITICAL"

    print("Automatic threat actions: PASSED")


def test_summary():
    print("\n[8] Testing summary...")

    fw = AdaptiveFirewall()

    fw.evaluate("source-1", 0.1)
    fw.evaluate("source-2", 0.95)

    summary = fw.summary()

    assert summary["total_requests"] == 2
    assert summary["allowed_requests"] == 1
    assert summary["blocked_requests"] == 1

    print("Summary: PASSED")


def main():
    print("=" * 60)
    print("ADAPTIVE FIREWALL TESTS")
    print("=" * 60)

    test_import()
    test_threat_classification()
    test_validation()
    test_allowlist()
    test_permanent_block()
    test_temporary_block()
    test_automatic_actions()
    test_summary()

    print("\n" + "=" * 60)
    print("ALL ADAPTIVE FIREWALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()