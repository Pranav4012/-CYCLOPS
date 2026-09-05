"""
Tamper-evident forensic chain-of-custody — the "Blockchain & Cybersecurity"
core, made genuinely useful rather than decorative.

The data diode already guarantees the enclave cannot be used to reach back into
production; this module guarantees that what the enclave records cannot be
silently altered afterwards.

Every alert becomes an evidence bundle containing:
- the alert
- the flow record
- a Merkle root over raw packet hashes
- the feature vector
- the exact model version that produced it

Bundles are batched into blocks. Each block carries the Merkle root of its
bundles and is hash-chained to the previous block, then signed by the sensor.

Block headers can be anchored to a permissioned ledger, so a committed root
retroactively freezes everything beneath it.

Uses only the Python standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from dataclasses import dataclass
from typing import List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Hashing and canonical serialization utilities.
# --------------------------------------------------------------------------- #

def _h(data: bytes) -> str:
    """Return a SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    """
    Deterministic serialization so hashes are reproducible across hosts.
    """

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


# --------------------------------------------------------------------------- #
# Merkle tree over per-bundle (or per-packet) hashes.
# Includes inclusion proof generation and verification.
# --------------------------------------------------------------------------- #

class MerkleTree:

    def __init__(self, leaves: List[str]):

        self.leaves = leaves[:] or [_h(b"empty")]

        self.levels: List[List[str]] = [
            self.leaves
        ]

        self._build()

    def _build(self):
        """Build the Merkle tree from leaves to root."""

        level = self.leaves

        while len(level) > 1:

            nxt = []

            for i in range(0, len(level), 2):

                a = level[i]

                # Duplicate the final node when there is an odd number
                # of hashes.
                b = (
                    level[i + 1]
                    if i + 1 < len(level)
                    else a
                )

                nxt.append(
                    _h(
                        bytes.fromhex(a) +
                        bytes.fromhex(b)
                    )
                )

            self.levels.append(nxt)

            level = nxt

    @property
    def root(self) -> str:
        """Return the Merkle root."""

        return self.levels[-1][0]

    def proof(
        self,
        index: int
    ) -> List[Tuple[str, str]]:
        """
        Generate an inclusion proof.

        Returns a list containing:
        (sibling_hash, "L" or "R")
        """

        proof = []

        for level in self.levels[:-1]:

            sib = index ^ 1

            if sib < len(level):

                side = (
                    "R"
                    if sib > index
                    else "L"
                )

                proof.append(
                    (
                        level[sib],
                        side
                    )
                )

            else:

                # Duplicate final node when there is no sibling.
                proof.append(
                    (
                        level[index],
                        "R"
                    )
                )

            index //= 2

        return proof

    @staticmethod
    def verify_proof(
        leaf: str,
        proof: List[Tuple[str, str]],
        root: str
    ) -> bool:
        """Verify a Merkle inclusion proof."""

        current_hash = leaf

        for sibling, side in proof:

            if side == "R":

                current_hash = _h(
                    bytes.fromhex(current_hash) +
                    bytes.fromhex(sibling)
                )

            else:

                current_hash = _h(
                    bytes.fromhex(sibling) +
                    bytes.fromhex(current_hash)
                )

        return current_hash == root


# --------------------------------------------------------------------------- #
# Evidence bundle.
# --------------------------------------------------------------------------- #

@dataclass
class EvidenceBundle:

    alert: dict
    flow_record: dict
    packet_hashes: List[str]
    feature_vector: dict
    model_id: str
    model_version: str

    def digest(self) -> str:
        """
        Create a cryptographic digest representing the complete
        evidence bundle.
        """

        pkt_root = MerkleTree(
            self.packet_hashes or [_h(b"-")]
        ).root

        payload = {
            "alert": self.alert,
            "flow": self.flow_record,
            "pkt_root": pkt_root,
            "features": self.feature_vector,
            "model": (
                f"{self.model_id}"
                f"@{self.model_version}"
            ),
        }

        return _h(
            canonical(payload)
        )


# --------------------------------------------------------------------------- #
# Ledger block.
# --------------------------------------------------------------------------- #

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
        """
        Calculate the deterministic hash of the block header.
        """

        header = {
            "index": self.index,
            "ts": round(
                self.ts,
                6
            ),
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "sensor_id": self.sensor_id,
        }

        return _h(
            canonical(header)
        )


# --------------------------------------------------------------------------- #
# Evidence Ledger.
# --------------------------------------------------------------------------- #

class EvidenceLedger:

    """
    Append-only, hash-chained, signed ledger of evidence bundles.

    Security guarantees:
    - Evidence bundles are individually hashed.
    - Bundle hashes are protected using a Merkle tree.
    - Blocks are linked using cryptographic hashes.
    - Block headers are authenticated using HMAC.
    - Blocks can be anchored to an external permissioned ledger.
    """

    def __init__(
        self,
        sensor_id: str,
        signing_key: bytes,
        batch_size: int = 8
    ):

        self.sensor_id = sensor_id

        self._key = signing_key

        self.batch_size = batch_size

        self.blocks: List[Block] = []

        self._pending: List[
            EvidenceBundle
        ] = []

        self._genesis()

    # ----------------------------------------------------------------------- #
    # Genesis block.
    # ----------------------------------------------------------------------- #

    def _genesis(self):
        """Create and sign the genesis block."""

        block = Block(
            index=0,
            ts=0.0,
            prev_hash="0" * 64,
            merkle_root=MerkleTree(
                [_h(b"genesis")]
            ).root,
            bundle_digests=[],
            sensor_id=self.sensor_id
        )

        block.signature = self._sign(
            block
        )

        self.blocks.append(
            block
        )

    # ----------------------------------------------------------------------- #
    # Signing.
    # ----------------------------------------------------------------------- #

    def _sign(
        self,
        block: Block
    ) -> str:
        """
        Create an HMAC-SHA256 signature for a block header.
        """

        return hmac.new(
            self._key,
            block.header_hash().encode(),
            hashlib.sha256
        ).hexdigest()

    # ----------------------------------------------------------------------- #
    # Adding and sealing evidence.
    # ----------------------------------------------------------------------- #

    def add(
        self,
        bundle: EvidenceBundle,
        ts: float
    ) -> Optional[Block]:
        """
        Add an evidence bundle.

        Automatically seals a block when batch_size is reached.
        """

        self._pending.append(
            bundle
        )

        if (
            len(self._pending)
            >= self.batch_size
        ):
            return self.seal(
                ts
            )

        return None

    def seal(
        self,
        ts: float
    ) -> Optional[Block]:
        """
        Close the current batch into a signed,
        hash-chained block.
        """

        if not self._pending:
            return None

        digests = [
            bundle.digest()
            for bundle in self._pending
        ]

        merkle_root = MerkleTree(
            digests
        ).root

        previous_block = (
            self.blocks[-1]
        )

        block = Block(
            index=previous_block.index + 1,
            ts=ts,
            prev_hash=(
                previous_block.header_hash()
            ),
            merkle_root=merkle_root,
            bundle_digests=digests,
            sensor_id=self.sensor_id
        )

        block.signature = self._sign(
            block
        )

        self.blocks.append(
            block
        )

        self._pending = []

        return block

    # ----------------------------------------------------------------------- #
    # External anchoring.
    # ----------------------------------------------------------------------- #

    def anchor(
        self,
        block_index: int
    ) -> str:
        """
        Commit a block header to a stubbed permissioned ledger.

        In production this can be replaced with a real
        permissioned blockchain or ledger implementation.
        """

        block = self.blocks[
            block_index
        ]

        reference = (
            "anchor://permissioned/"
            + block.header_hash()[:32]
        )

        block.anchored = True

        block.anchor_ref = (
            reference
        )

        return reference

    # ----------------------------------------------------------------------- #
    # Individual block verification.
    # NEW SECURITY FEATURE.
    # ----------------------------------------------------------------------- #

    def verify_block(
        self,
        block_index: int
    ) -> bool:
        """
        Verify the cryptographic integrity of an individual block.

        Checks:
        1. Valid block index.
        2. HMAC signature integrity.
        3. Merkle root integrity for evidence blocks.
        """

        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            return False

        block = self.blocks[
            block_index
        ]

        # Verify HMAC signature.
        if not hmac.compare_digest(
            block.signature,
            self._sign(block)
        ):
            return False

        # Genesis has no evidence bundle digests.
        if block.index == 0:
            return True

        # Recalculate Merkle root from the stored
        # evidence bundle digests.
        calculated_root = MerkleTree(
            block.bundle_digests
        ).root

        if (
            calculated_root
            != block.merkle_root
        ):
            return False

        return True

    # ----------------------------------------------------------------------- #
    # Full chain verification.
    # ----------------------------------------------------------------------- #

    def verify_chain(
        self
    ) -> Tuple[
        bool,
        Optional[int]
    ]:
        """
        Verify the complete ledger.

        Checks:
        1. Every block's signature.
        2. Every evidence block's Merkle root.
        3. Hash linkage between consecutive blocks.

        Returns:
            (True, None)
                if the chain is intact.

            (False, block_index)
                if tampering is detected.
        """

        for i, current_block in enumerate(
            self.blocks
        ):

            # Verify the block itself.
            if not self.verify_block(i):

                return (
                    False,
                    i
                )

            # Genesis has no predecessor.
            if i == 0:
                continue

            previous_block = (
                self.blocks[i - 1]
            )

            # Verify the hash chain.
            if (
                current_block.prev_hash
                != previous_block.header_hash()
            ):

                return (
                    False,
                    i
                )

        return (
            True,
            None
        )

    # ----------------------------------------------------------------------- #
    # Ledger summary.
    # ----------------------------------------------------------------------- #

    def summary(
        self
    ) -> dict:
        """
        Return a concise integrity and status summary.
        """

        chain_ok, broken_block = (
            self.verify_chain()
        )

        return {
            "sensor_id": self.sensor_id,

            "blocks": len(
                self.blocks
            ),

            "pending": len(
                self._pending
            ),

            "anchored_blocks": sum(
                1
                for block in self.blocks
                if block.anchored
            ),

            "chain_intact": chain_ok,

            "first_broken_block":
                broken_block,

            "head": (
                self.blocks[-1]
                .header_hash()[:16]
                if self.blocks
                else None
            ),
        }