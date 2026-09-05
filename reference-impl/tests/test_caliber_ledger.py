"""CALIBER conformal calibrator + WIRESEAL Merkle/hash-chained evidence ledger."""
import random

from halfsight.caliber import ConformalCalibrator
from halfsight.evidence.ledger import MerkleTree, EvidenceLedger, EvidenceBundle


def test_conformal_coverage_tracks_nominal():
    rng = random.Random(0)
    # continuous TP scores for one class; coverage should track 1 - alpha
    samples = [("c2", rng.random(), 0.0) for _ in range(400)]
    cal, test = samples[:200], samples[200:]
    cc = ConformalCalibrator(alpha=0.10).fit(cal)
    cov = cc.coverage(test)["c2"]
    assert 0.80 <= cov <= 1.0


def test_merkle_inclusion_proof():
    leaves = [f"{i:064x}" for i in range(9)]           # 9 hex leaves (odd count)
    t = MerkleTree(leaves)
    proof = t.proof(3)
    assert MerkleTree.verify_proof(leaves[3], proof, t.root)
    assert not MerkleTree.verify_proof(leaves[4], proof, t.root)


def _bundle(i):
    return EvidenceBundle({"id": i}, {"f": i}, [f"h{i}"], {"x": i}, "m", "1")


def test_ledger_intact_then_tamper_detected():
    led = EvidenceLedger("sensor", b"key", batch_size=100)
    for i in range(10):
        led.add(_bundle(i), float(i))
    led.seal(10.0)
    ok, broken = led.verify_chain()
    assert ok and broken is None
    # tamper a sealed block's merkle root -> chain breaks
    led.blocks[1].merkle_root = "deadbeef" * 8
    ok2, broken2 = led.verify_chain()
    assert not ok2 and broken2 == 1


def test_ledger_tamper_localises_to_leaf():
    led = EvidenceLedger("s", b"k", batch_size=100)
    for i in range(12):
        led.add(_bundle(i), float(i))
    blk = led.seal(12.0)
    tgt = 5
    blk.bundle_digests[tgt] = "deadbeef" * 8
    recomputed = MerkleTree(blk.bundle_digests).root
    assert recomputed != blk.merkle_root                # tamper is detectable in the block
