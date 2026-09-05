import sys

# Allow imports from reference-impl
sys.path.insert(0, "reference-impl")

from halfsight.caliber import ConformalCalibrator
from halfsight.evidence.ledger import EvidenceLedger, EvidenceBundle


print("=" * 50)
print("PERSON 5 SECURITY MODULE TEST")
print("=" * 50)


# -------------------------------------------------
# TEST 1: Evidence Ledger
# -------------------------------------------------

print("\n[1] Testing Evidence Ledger...")

ledger = EvidenceLedger(
    sensor_id="sensor-01",
    signing_key=b"super-secret-test-key",
    batch_size=2
)


bundle1 = EvidenceBundle(
    alert={
        "type": "port_scan",
        "severity": "high"
    },
    flow_record={
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP"
    },
    packet_hashes=[
        "a" * 64,
        "b" * 64
    ],
    feature_vector={
        "packet_count": 100,
        "bytes": 5000
    },
    model_id="threat-detector",
    model_version="1.0"
)


bundle2 = EvidenceBundle(
    alert={
        "type": "ddos",
        "severity": "critical"
    },
    flow_record={
        "src_ip": "10.0.0.3",
        "dst_ip": "10.0.0.2",
        "protocol": "UDP"
    },
    packet_hashes=[
        "c" * 64,
        "d" * 64
    ],
    feature_vector={
        "packet_count": 10000,
        "bytes": 500000
    },
    model_id="threat-detector",
    model_version="1.0"
)


# Add first bundle
result1 = ledger.add(bundle1, ts=1000.0)

print("First bundle added")
assert result1 is None


# Add second bundle -> batch_size = 2, so block should seal
block = ledger.add(bundle2, ts=1001.0)

assert block is not None

print(f"Block created: {block.index}")
print(f"Merkle root: {block.merkle_root[:16]}...")


# Verify blockchain / hash chain
ok, broken = ledger.verify_chain()

assert ok is True
assert broken is None

print("Chain verification: PASSED")


# Anchor the block
anchor = ledger.anchor(block.index)

print(f"Anchor created: {anchor}")


# Print summary
summary = ledger.summary()

print("\nLedger Summary:")

for key, value in summary.items():
    print(f"{key}: {value}")


# -------------------------------------------------
# TEST 2: Caliber import / basic initialization
# -------------------------------------------------

print("\n[2] Testing Caliber module...")

calibrator = ConformalCalibrator()

print("ConformalCalibrator created successfully")


# -------------------------------------------------
# FINAL RESULT
# -------------------------------------------------

print("\n" + "=" * 50)
print("ALL PERSON 5 TESTS PASSED")
print("=" * 50)