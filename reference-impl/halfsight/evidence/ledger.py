"""
Tamper-evident forensic chain-of-custody.

The evidence ledger records security alerts as evidence bundles and protects
them using:

- SHA-256 hashes
- Merkle trees
- Merkle inclusion proofs
- Hash-chained blocks
- HMAC signatures
- Permissioned-ledger anchoring

Only the Python standard library is used.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from dataclasses import dataclass
from typing import List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Hashing and canonical serialization
# --------------------------------------------------------------------------- #

def _h(data: bytes) -> str:
    """Return a SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    """
    Deterministic serialization.

    Sorting keys and removing unnecessary whitespace ensures that the same
    logical object produces the same bytes and therefore the same hash.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":")
    ).encode()


# --------------------------------------------------------------------------- #
# Merkle tree
# --------------------------------------------------------------------------- #

class MerkleTree:
    """
    Merkle tree over hexadecimal SHA-256 hashes.

    Supports:
    - root generation
    - inclusion proof generation
    - inclusion proof verification
    """

    def __init__(self, leaves: List[str]):
        self.leaves = leaves[:] or [_h(b"empty")]
        self.levels: List[List[str]] = [self.leaves]
        self._build()

    def _build(self) -> None:
        """Build the Merkle tree from leaves to root."""

        level = self.leaves

        while len(level) > 1:

            nxt = []

            for i in range(0, len(level), 2):

                left = level[i]

                if i + 1 < len(level):
                    right = level[i + 1]
                else:
                    # Duplicate the final node when the level has odd size.
                    right = left

                parent = _h(
                    bytes.fromhex(left) +
                    bytes.fromhex(right)
                )

                nxt.append(parent)

            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> str:
        """Return the Merkle root."""
        return self.levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Generate an inclusion proof.

        Each tuple contains:

            (sibling_hash, side)

        side:
            "L" -> sibling is on the left
            "R" -> sibling is on the right
        """

        if index < 0 or index >= len(self.leaves):
            raise IndexError(
                f"Invalid Merkle leaf index: {index}"
            )

        proof: List[Tuple[str, str]] = []

        for level in self.levels[:-1]:

            sibling_index = index ^ 1

            if sibling_index < len(level):

                side = (
                    "R"
                    if sibling_index > index
                    else "L"
                )

                proof.append(
                    (
                        level[sibling_index],
                        side
                    )
                )

            else:
                # Odd node was duplicated while building the tree.
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
        """
        Verify a Merkle inclusion proof.

        Returns True only when the supplied leaf and proof reconstruct
        the supplied Merkle root.
        """

        current_hash = leaf

        try:

            for sibling_hash, side in proof:

                if side == "R":

                    current_hash = _h(
                        bytes.fromhex(current_hash) +
                        bytes.fromhex(sibling_hash)
                    )

                elif side == "L":

                    current_hash = _h(
                        bytes.fromhex(sibling_hash) +
                        bytes.fromhex(current_hash)
                    )

                else:
                    # Invalid proof direction.
                    return False

        except (ValueError, TypeError):
            # Handles malformed hashes or malformed proof data.
            return False

        return hmac.compare_digest(
            current_hash,
            root
        )


# --------------------------------------------------------------------------- #
# Evidence bundle
# --------------------------------------------------------------------------- #

@dataclass
class EvidenceBundle:
    """
    A forensic evidence record.

    Each bundle contains the security alert, flow information, packet hashes,
    extracted features, and the exact ML model version involved.
    """

    alert: dict
    flow_record: dict
    packet_hashes: List[str]
    feature_vector: dict
    model_id: str
    model_version: str

    def digest(self) -> str:
        """
        Produce a deterministic SHA-256 digest for this evidence bundle.
        """

        packet_tree = MerkleTree(
            self.packet_hashes or [_h(b"-")]
        )

        payload = {
            "alert": self.alert,
            "flow": self.flow_record,
            "pkt_root": packet_tree.root,
            "features": self.feature_vector,
            "model": (
                f"{self.model_id}@"
                f"{self.model_version}"
            ),
        }

        return _h(
            canonical(payload)
        )


# --------------------------------------------------------------------------- #
# Block
# --------------------------------------------------------------------------- #

@dataclass
class Block:
    """
    A batch of evidence bundles.

    Blocks are chained together using the previous block's header hash.
    """

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
        Return the deterministic hash of this block's header.
        """

        header = {
            "index": self.index,
            "ts": round(self.ts, 6),
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "sensor_id": self.sensor_id,
        }

        return _h(
            canonical(header)
        )


# --------------------------------------------------------------------------- #
# Evidence ledger
# --------------------------------------------------------------------------- #

class EvidenceLedger:
    """
    Append-only tamper-evident evidence ledger.

    Features:
    - evidence bundle hashing
    - Merkle roots
    - Merkle inclusion proofs
    - hash-chained blocks
    - HMAC signatures
    - block anchoring
    - chain verification
    """

    def __init__(
        self,
        sensor_id: str,
        signing_key: bytes,
        batch_size: int = 8
    ):

        if batch_size <= 0:
            raise ValueError(
                "batch_size must be greater than zero"
            )

        self.sensor_id = sensor_id
        self._key = signing_key
        self.batch_size = batch_size

        self.blocks: List[Block] = []
        self._pending: List[EvidenceBundle] = []

        self._genesis()

    # ----------------------------------------------------------------------- #
    # Genesis
    # ----------------------------------------------------------------------- #

    def _genesis(self) -> None:
        """Create the genesis block."""

        genesis_root = MerkleTree(
            [_h(b"genesis")]
        ).root

        block = Block(
            index=0,
            ts=0.0,
            prev_hash="0" * 64,
            merkle_root=genesis_root,
            bundle_digests=[],
            sensor_id=self.sensor_id,
        )

        block.signature = self._sign(
            block
        )

        self.blocks.append(
            block
        )

    # ----------------------------------------------------------------------- #
    # Signing
    # ----------------------------------------------------------------------- #

    def _sign(
        self,
        block: Block
    ) -> str:
        """Create an HMAC signature for a block header."""

        return hmac.new(
            self._key,
            block.header_hash().encode(),
            hashlib.sha256
        ).hexdigest()

    # ----------------------------------------------------------------------- #
    # Adding and sealing evidence
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

        if len(self._pending) >= self.batch_size:
            return self.seal(
                ts
            )

        return None

    def seal(
        self,
        ts: float
    ) -> Optional[Block]:
        """
        Convert pending evidence bundles into a signed block.
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

        previous_block = self.blocks[-1]

        block = Block(
            index=previous_block.index + 1,
            ts=ts,
            prev_hash=previous_block.header_hash(),
            merkle_root=merkle_root,
            bundle_digests=digests,
            sensor_id=self.sensor_id,
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
    # NEW FEATURE: Evidence bundle inclusion proofs
    # ----------------------------------------------------------------------- #

    def bundle_proof(
        self,
        block_index: int,
        bundle_index: int
    ) -> dict:
        """
        Generate an inclusion proof for an evidence bundle.

        The returned proof can later be used to prove that a particular
        evidence bundle was included in a specific block without exposing
        all other bundles.
        """

        if block_index < 0 or block_index >= len(self.blocks):
            raise IndexError(
                f"Invalid block index: {block_index}"
            )

        block = self.blocks[
            block_index
        ]

        if not block.bundle_digests:
            raise ValueError(
                "Block does not contain evidence bundles"
            )

        if (
            bundle_index < 0
            or bundle_index >= len(block.bundle_digests)
        ):
            raise IndexError(
                f"Invalid bundle index: {bundle_index}"
            )

        tree = MerkleTree(
            block.bundle_digests
        )

        return {
            "block_index": block.index,
            "bundle_index": bundle_index,
            "bundle_digest": (
                block.bundle_digests[
                    bundle_index
                ]
            ),
            "proof": tree.proof(
                bundle_index
            ),
            "merkle_root": tree.root,
        }

    def verify_bundle_proof(
        self,
        proof_record: dict
    ) -> bool:
        """
        Verify an evidence bundle inclusion proof.

        The proof must:
        - reference a valid block
        - match that block's Merkle root
        - reconstruct the Merkle root successfully
        """

        try:

            block_index = proof_record[
                "block_index"
            ]

            bundle_digest = proof_record[
                "bundle_digest"
            ]

            proof = proof_record[
                "proof"
            ]

            claimed_root = proof_record[
                "merkle_root"
            ]

            if (
                block_index < 0
                or block_index >= len(self.blocks)
            ):
                return False

            block = self.blocks[
                block_index
            ]

            # The proof must correspond to the actual block root.
            if not hmac.compare_digest(
                claimed_root,
                block.merkle_root
            ):
                return False

            return MerkleTree.verify_proof(
                bundle_digest,
                proof,
                block.merkle_root
            )

        except (
            KeyError,
            TypeError,
            ValueError
        ):
            return False

    # ----------------------------------------------------------------------- #
    # Anchoring
    # ----------------------------------------------------------------------- #

    def anchor(
        self,
        block_index: int
    ) -> str:
        """
        Commit a block header to the stubbed permissioned ledger.
        """

        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            raise IndexError(
                f"Invalid block index: {block_index}"
            )

        block = self.blocks[
            block_index
        ]

        reference = (
            "anchor://permissioned/"
            + block.header_hash()[:32]
        )

        block.anchored = True
        block.anchor_ref = reference

        return reference

    # ----------------------------------------------------------------------- #
    # Verification
    # ----------------------------------------------------------------------- #

    def verify_chain(
        self
    ) -> Tuple[bool, Optional[int]]:
        """
        Verify the entire blockchain-style evidence chain.

        Returns:

            (True, None)

        when the chain is intact.

        Returns:

            (False, block_index)

        when tampering is detected.
        """

        # Verify genesis signature.
        genesis = self.blocks[0]

        if not hmac.compare_digest(
            genesis.signature,
            self._sign(genesis)
        ):
            return False, 0

        for i in range(
            1,
            len(self.blocks)
        ):

            current = self.blocks[i]
            previous = self.blocks[i - 1]

            # Previous hash chain.
            if not hmac.compare_digest(
                current.prev_hash,
                previous.header_hash()
            ):
                return False, i

            # Recalculate Merkle root.
            if current.bundle_digests:

                calculated_root = MerkleTree(
                    current.bundle_digests
                ).root

                if not hmac.compare_digest(
                    current.merkle_root,
                    calculated_root
                ):
                    return False, i

            # Verify HMAC signature.
            if not hmac.compare_digest(
                current.signature,
                self._sign(current)
            ):
                return False, i

        return True, None

    # ----------------------------------------------------------------------- #
    # Summary
    # ----------------------------------------------------------------------- #

    def summary(self) -> dict:
        """Return a compact ledger status summary."""

        intact, broken_index = (
            self.verify_chain()
        )

        return {
            "sensor_id": self.sensor_id,
            "blocks": len(self.blocks),
            "pending": len(self._pending),
            "anchored_blocks": sum(
                1
                for block in self.blocks
                if block.anchored
            ),
            "chain_intact": intact,
            "first_broken_block": broken_index,
            "head": (
                self.blocks[-1]
                .header_hash()[:16]
                if self.blocks
                else None
            ),
        }