import sys

# Allow imports from reference-impl
sys.path.insert(0, "reference-impl")

from halfsight.caliber import ConformalCalibrator
from halfsight.evidence.ledger import (
    EvidenceBundle,
    EvidenceLedger,
)


LINE = "=" * 50


def create_bundle(number: int = 1) -> EvidenceBundle:
    """Create a sample evidence bundle for testing."""

    return EvidenceBundle(
        alert={
            "id": f"alert-{number}",
            "threat": "test-threat",
            "severity": "high",
        },
        flow_record={
            "flow_id": f"flow-{number}",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
        },
        packet_hashes=[
            f"{number:064x}",
            f"{number + 1:064x}",
        ],
        feature_vector={
            "entropy": 0.91,
            "packet_count": 25,
        },
        model_id="test-model",
        model_version="1.0",
    )


def create_ledger(
    batch_size: int = 2
) -> EvidenceLedger:
    """Create a fresh ledger for an isolated test."""

    return EvidenceLedger(
        sensor_id="sensor-01",
        signing_key=b"person-5-test-key",
        batch_size=batch_size,
    )


# --------------------------------------------------------------------------- #
# Basic ledger tests.
# --------------------------------------------------------------------------- #

def test_basic_ledger():
    print("\n[1] Testing Evidence Ledger...")

    ledger = create_ledger(
        batch_size=2
    )

    bundle_1 = create_bundle(1)
    bundle_2 = create_bundle(2)

    result = ledger.add(
        bundle_1,
        ts=1000.0
    )

    assert result is None

    print("First bundle added")

    block = ledger.add(
        bundle_2,
        ts=1001.0
    )

    assert block is not None

    print(
        f"Block created: {block.index}"
    )

    print(
        f"Merkle root: "
        f"{block.merkle_root[:16]}..."
    )

    ok, broken = (
        ledger.verify_chain()
    )

    assert ok is True
    assert broken is None

    print(
        "Chain verification: PASSED"
    )

    anchor = ledger.anchor(
        block.index
    )

    assert block.anchored is True
    assert block.anchor_ref == anchor

    print(
        f"Anchor created: {anchor}"
    )

    summary = ledger.summary()

    print("\nLedger Summary:")

    for key, value in summary.items():
        print(
            f"{key}: {value}"
        )


# --------------------------------------------------------------------------- #
# Tampering detection tests.
# --------------------------------------------------------------------------- #

def test_merkle_root_tampering():
    print(
        "\n[2] Testing Merkle root tampering..."
    )

    ledger = create_ledger()

    ledger.add(
        create_bundle(1),
        ts=1000.0
    )

    block = ledger.add(
        create_bundle(2),
        ts=1001.0
    )

    assert block is not None

    # Modify the stored Merkle root.
    block.merkle_root = (
        "0" * 64
    )

    ok, broken = (
        ledger.verify_chain()
    )

    assert ok is False
    assert broken == 1

    print(
        "Merkle root tampering: DETECTED"
    )


def test_bundle_digest_tampering():
    print(
        "\n[3] Testing bundle digest tampering..."
    )

    ledger = create_ledger()

    ledger.add(
        create_bundle(1),
        ts=1000.0
    )

    block = ledger.add(
        create_bundle(2),
        ts=1001.0
    )

    assert block is not None

    # Modify a stored evidence digest.
    block.bundle_digests[0] = (
        "f" * 64
    )

    ok, broken = (
        ledger.verify_chain()
    )

    assert ok is False
    assert broken == 1

    print(
        "Bundle digest tampering: DETECTED"
    )


def test_signature_tampering():
    print(
        "\n[4] Testing signature tampering..."
    )

    ledger = create_ledger()

    ledger.add(
        create_bundle(1),
        ts=1000.0
    )

    block = ledger.add(
        create_bundle(2),
        ts=1001.0
    )

    assert block is not None

    # Modify the block signature.
    block.signature = (
        "a" * 64
    )

    ok, broken = (
        ledger.verify_chain()
    )

    assert ok is False
    assert broken == 1

    print(
        "Signature tampering: DETECTED"
    )


def test_previous_hash_tampering():
    print(
        "\n[5] Testing previous hash tampering..."
    )

    ledger = create_ledger(
        batch_size=1
    )

    first_block = ledger.add(
        create_bundle(1),
        ts=1000.0
    )

    second_block = ledger.add(
        create_bundle(2),
        ts=1001.0
    )

    assert first_block is not None
    assert second_block is not None

    # Modify the chain reference.
    second_block.prev_hash = (
        "b" * 64
    )

    ok, broken = (
        ledger.verify_chain()
    )

    assert ok is False
    assert broken == 2

    print(
        "Previous hash tampering: DETECTED"
    )


def test_invalid_block_index():
    print(
        "\n[6] Testing invalid block verification..."
    )

    ledger = create_ledger()

    result = ledger.verify_block(
        999
    )

    assert result is False

    print(
        "Invalid block index: HANDLED"
    )


# --------------------------------------------------------------------------- #
# Caliber test.
# --------------------------------------------------------------------------- #

def test_caliber():
    print(
        "\n[7] Testing Caliber module..."
    )

    calibrator = (
        ConformalCalibrator()
    )

    assert calibrator is not None

    print(
        "ConformalCalibrator created successfully"
    )


# --------------------------------------------------------------------------- #
# Main test runner.
# --------------------------------------------------------------------------- #

def main():

    print(LINE)
    print(
        "PERSON 5 SECURITY MODULE TEST"
    )
    print(LINE)

    test_basic_ledger()

    test_merkle_root_tampering()

    test_bundle_digest_tampering()

    test_signature_tampering()

    test_previous_hash_tampering()

    test_invalid_block_index()

    test_caliber()

    print("\n" + LINE)
    print(
        "ALL PERSON 5 TESTS PASSED"
    )
    print(LINE)


if __name__ == "__main__":
    main()