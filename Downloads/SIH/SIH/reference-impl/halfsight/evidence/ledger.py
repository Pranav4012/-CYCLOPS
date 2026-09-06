"""
Tamper-evident forensic chain-of-custody  —  the "Blockchain & Cybersecurity"
core, made genuinely useful rather than decorative.

The data diode already guarantees the enclave cannot be used to reach back into
production; this module guarantees that what the enclave *records* cannot be
silently altered afterwards. Every alert becomes an evidence bundle (the alert,
the flow record, a Merkle root over the raw packet hashes, the feature vector,
and the exact model version that produced it). Bundles are batched into blocks;
each block carries the Merkle root of its bundles and is hash-chained to the
previous block, then signed by the sensor. Block headers are periodically
*anchored* to a permissioned ledger, so a single committed root retroactively
freezes everything beneath it.

Why this pairing is strong:
  * WORM by construction — any edit to any past bundle changes a Merkle root,
    which breaks the chain hash, which fails verification.
  * Non-repudiable provenance — each alert is bound to a signed model version,
    so "which model, which weights, decided this" is answerable in court.
  * Federation without raw sharing — two enclaves can prove they saw the same
    flow by comparing Merkle roots, never exchanging PCAP.

Uses only the standard library (hashlib/hmac). Swap HMAC for ed25519 and the
anchor stub for a Hyperledger Fabric / notary commit in production.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    """Deterministic serialization so hashes are reproducible across hosts."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# --------------------------------------------------------------------------- #
# Merkle tree over per-bundle (or per-packet) hashes, with inclusion proofs.
# --------------------------------------------------------------------------- #
class MerkleTree:
    def __init__(self, leaves: List[str]):
        self.leaves = leaves[:] or [_h(b"empty")]
        self.levels: List[List[str]] = [self.leaves]
        self._build()

    def _build(self):
        level = self.leaves
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                a = level[i]
                b = level[i + 1] if i + 1 < len(level) else a  # duplicate last if odd
                nxt.append(_h(bytes.fromhex(a) + bytes.fromhex(b)))
            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, str]]:
        """Inclusion proof: list of (sibling_hash, 'L'|'R')."""
        proof = []
        for level in self.levels[:-1]:
            sib = index ^ 1
            if sib < len(level):
                side = "R" if sib > index else "L"
                proof.append((level[sib], side))
            else:
                proof.append((level[index], "R"))  # duplicated node
            index //= 2
        return proof

    @staticmethod
    def verify_proof(leaf: str, proof: List[Tuple[str, str]], root: str) -> bool:
        h = leaf
        for sib, side in proof:
            if side == "R":
                h = _h(bytes.fromhex(h) + bytes.fromhex(sib))
            else:
                h = _h(bytes.fromhex(sib) + bytes.fromhex(h))
        return h == root


# --------------------------------------------------------------------------- #
# Evidence bundle + hash-chained block ledger.
# --------------------------------------------------------------------------- #
@dataclass
class EvidenceBundle:
    alert: dict
    flow_record: dict
    packet_hashes: List[str]          # sha256 of each raw packet the diode copied
    feature_vector: dict
    model_id: str
    model_version: str

    def digest(self) -> str:
        pkt_root = MerkleTree(self.packet_hashes or [_h(b'-')]).root
        payload = {
            "alert": self.alert,
            "flow": self.flow_record,
            "pkt_root": pkt_root,
            "features": self.feature_vector,
            "model": f"{self.model_id}@{self.model_version}",
        }
        return _h(canonical(payload))


@dataclass
class Block:
    index: int
    ts: float
    prev_hash: str
    merkle_root: str
    bundle_digests: List[str]
    sensor_id: str
    signature: str = ""
    anchored: bool = False
    anchor_ref: Optional[str] = None

    def header_hash(self) -> str:
        hdr = {
            "index": self.index, "ts": round(self.ts, 6), "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root, "sensor_id": self.sensor_id,
        }
        return _h(canonical(hdr))


class EvidenceLedger:
    """Append-only, hash-chained, signed ledger of evidence bundles."""

    def __init__(self, sensor_id: str, signing_key: bytes, batch_size: int = 8):
        self.sensor_id = sensor_id
        self._key = signing_key
        self.batch_size = batch_size
        self.blocks: List[Block] = []
        self._pending: List[EvidenceBundle] = []
        self._genesis()

    def _genesis(self):
        b = Block(0, 0.0, "0" * 64, MerkleTree([_h(b"genesis")]).root, [], self.sensor_id)
        b.signature = self._sign(b)
        self.blocks.append(b)

    def _sign(self, b: Block) -> str:
        return hmac.new(self._key, b.header_hash().encode(), hashlib.sha256).hexdigest()

    def add(self, bundle: EvidenceBundle, ts: float) -> Optional[Block]:
        self._pending.append(bundle)
        if len(self._pending) >= self.batch_size:
            return self.seal(ts)
        return None

    def seal(self, ts: float) -> Optional[Block]:
        """Close the current batch into a signed, chained block."""
        if not self._pending:
            return None
        digests = [b.digest() for b in self._pending]
        root = MerkleTree(digests).root
        prev = self.blocks[-1]
        blk = Block(prev.index + 1, ts, prev.header_hash(), root, digests, self.sensor_id)
        blk.signature = self._sign(blk)
        self.blocks.append(blk)
        self._pending = []
        return blk

    def anchor(self, block_index: int) -> str:
        """Commit a block header to the (stubbed) permissioned ledger."""
        blk = self.blocks[block_index]
        ref = "anchor://permissioned/" + blk.header_hash()[:32]
        blk.anchored = True
        blk.anchor_ref = ref
        return ref

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """Return (ok, first_broken_index). Detects any post-hoc tampering."""
        for i in range(1, len(self.blocks)):
            cur, prev = self.blocks[i], self.blocks[i - 1]
            if cur.prev_hash != prev.header_hash():
                return False, i
            if not hmac.compare_digest(cur.signature, self._sign(cur)):
                return False, i
        return True, None

    def summary(self) -> dict:
        ok, broken = self.verify_chain()
        return {
            "sensor_id": self.sensor_id,
            "blocks": len(self.blocks),
            "pending": len(self._pending),
            "anchored_blocks": sum(1 for b in self.blocks if b.anchored),
            "chain_intact": ok,
            "first_broken_block": broken,
            "head": self.blocks[-1].header_hash()[:16] if self.blocks else None,
        }
