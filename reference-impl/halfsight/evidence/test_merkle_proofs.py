import sys


# Allow imports from reference-impl.
sys.path.insert(
    0,
    "reference-impl"
)


from halfsight.evidence.ledger import (
    EvidenceBundle,
    EvidenceLedger,
)


print("=" * 55)
print("MERKLE INCLUSION PROOF TEST")
print("=" * 55)


def make_bundle(
    number: int
) -> EvidenceBundle:

    return EvidenceBundle(
        alert={
            "id": number,
            "type": "suspicious-traffic",
        },
        flow_record={
            "src_ip": f"10.0.0.{number}",
            "dst_ip": "192.168.1.10",
            "protocol": "TCP",
        },
        packet_hashes=[
            f"{number:064x}",
            f"{number + 1:064x}",
        ],
        feature_vector={
            "packet_count": number * 10,
            "byte_count": number * 100,
        },
        model_id="threat-detector",
        model_version="1.0.0",
    )


print("\n[1] Creating evidence ledger...")

ledger = EvidenceLedger(
    sensor_id="sensor-proof-01",
    signing_key=b"person5-secret-key",
    batch_size=4,
)

print(
    "EvidenceLedger created successfully"
)


print("\n[2] Adding evidence bundles...")

for i in range(1, 5):

    block = ledger.add(
        make_bundle(i),
        ts=float(i)
    )

print(
    "Four bundles added"
)


if block is None:
    raise AssertionError(
        "Expected block to be created"
    )

print(
    f"Block created: {block.index}"
)

print(
    f"Merkle root: "
    f"{block.merkle_root[:16]}..."
)


print("\n[3] Generating inclusion proof...")

proof_record = ledger.bundle_proof(
    block_index=1,
    bundle_index=2,
)

print(
    "Inclusion proof generated"
)

print(
    f"Bundle index: "
    f"{proof_record['bundle_index']}"
)

print(
    f"Proof steps: "
    f"{len(proof_record['proof'])}"
)


print("\n[4] Verifying valid proof...")

valid = ledger.verify_bundle_proof(
    proof_record
)

assert valid

print(
    "Valid inclusion proof: PASSED"
)


print("\n[5] Testing modified bundle digest...")

tampered_digest = (
    proof_record.copy()
)

tampered_digest[
    "bundle_digest"
] = "0" * 64

valid = ledger.verify_bundle_proof(
    tampered_digest
)

assert not valid

print(
    "Bundle digest tampering: DETECTED"
)


print("\n[6] Testing wrong Merkle root...")

tampered_root = (
    proof_record.copy()
)

tampered_root[
    "merkle_root"
] = "f" * 64

valid = ledger.verify_bundle_proof(
    tampered_root
)

assert not valid

print(
    "Wrong Merkle root: DETECTED"
)


print("\n[7] Testing modified proof...")

tampered_proof = (
    proof_record.copy()
)

tampered_proof[
    "proof"
] = list(
    proof_record["proof"]
)

if tampered_proof["proof"]:

    original_hash, side = (
        tampered_proof["proof"][0]
    )

    replacement = (
        "0" * 64
        if original_hash != "0" * 64
        else "f" * 64
    )

    tampered_proof["proof"][0] = (
        replacement,
        side,
    )

valid = ledger.verify_bundle_proof(
    tampered_proof
)

assert not valid

print(
    "Merkle proof tampering: DETECTED"
)


print("\n[8] Testing invalid block index...")

try:

    ledger.bundle_proof(
        block_index=999,
        bundle_index=0,
    )

    raise AssertionError(
        "Invalid block index was accepted"
    )

except IndexError:

    print(
        "Invalid block index: HANDLED"
    )


print("\n[9] Testing invalid bundle index...")

try:

    ledger.bundle_proof(
        block_index=1,
        bundle_index=999,
    )

    raise AssertionError(
        "Invalid bundle index was accepted"
    )

except IndexError:

    print(
        "Invalid bundle index: HANDLED"
    )


print("\n" + "=" * 55)
print("ALL MERKLE INCLUSION PROOF TESTS PASSED")
print("=" * 55)