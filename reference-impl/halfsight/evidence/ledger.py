"""
Tamper-evident forensic chain-of-custody — the "Blockchain & Cybersecurity"
core, made genuinely useful rather than decorative.

The data diode already guarantees the enclave cannot be used to reach back into
production; this module guarantees that what the enclave records cannot be
silently altered afterwards.

Every alert becomes an evidence bundle containing:
- alert
- flow record
- Merkle root over raw packet hashes
- feature vector
- exact model version

Bundles are batched into blocks.

Each block:
- contains a Merkle root of bundle digests
- links cryptographically to the previous block
- is signed by the sensor
- can be anchored to a permissioned ledger
- can be persisted to JSON and reloaded with integrity verification

Uses only the Python standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Hashing and canonical serialization
# --------------------------------------------------------------------------- #

def _h(data: bytes) -> str:
    """Return SHA-256 hexadecimal digest."""
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    """
    Deterministic serialization.

    Ensures hashes are reproducible across different hosts and runs.
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
    - Merkle root generation
    - Inclusion proof generation
    - Inclusion proof verification
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
                a = level[i]

                # Duplicate final node if there is an odd number of nodes.
                if i + 1 < len(level):
                    b = level[i + 1]
                else:
                    b = a

                combined = (
                    bytes.fromhex(a)
                    + bytes.fromhex(b)
                )

                nxt.append(
                    _h(combined)
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
        Generate a Merkle inclusion proof.

        Returns a list of:

            (sibling_hash, side)

        where side is:
            "L" -> sibling is on the left
            "R" -> sibling is on the right
        """

        if index < 0 or index >= len(self.leaves):
            raise IndexError("Invalid bundle index")

        proof = []

        for level in self.levels[:-1]:

            sibling_index = index ^ 1

            if sibling_index < len(level):

                if sibling_index > index:
                    side = "R"
                else:
                    side = "L"

                proof.append(
                    (
                        level[sibling_index],
                        side
                    )
                )

            else:
                # Odd node was duplicated during tree construction.
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

        Returns True only if the leaf and proof reconstruct the supplied root.
        """

        current_hash = leaf

        for sibling_hash, side in proof:

            if side == "R":

                current_hash = _h(
                    bytes.fromhex(current_hash)
                    + bytes.fromhex(sibling_hash)
                )

            elif side == "L":

                current_hash = _h(
                    bytes.fromhex(sibling_hash)
                    + bytes.fromhex(current_hash)
                )

            else:
                return False

        return current_hash == root


# --------------------------------------------------------------------------- #
# Evidence bundle
# --------------------------------------------------------------------------- #

@dataclass
class EvidenceBundle:
    """
    A complete forensic evidence record.

    Each bundle represents evidence associated with a security alert.
    """

    alert: dict
    flow_record: dict
    packet_hashes: List[str]
    feature_vector: dict
    model_id: str
    model_version: str

    def digest(self) -> str:
        """
        Produce a tamper-evident digest for the evidence bundle.
        """

        packet_root = MerkleTree(
            self.packet_hashes or [_h(b"-")]
        ).root

        payload = {
            "alert": self.alert,
            "flow": self.flow_record,
            "pkt_root": packet_root,
            "features": self.feature_vector,
            "model": (
                f"{self.model_id}"
                f"@"
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
    A batch of evidence bundles stored as one cryptographically linked block.
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
        Hash the immutable block header.

        The header intentionally excludes mutable anchor metadata.
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
    Append-only, hash-chained, signed ledger of evidence bundles.
    """

    STORAGE_VERSION = 1

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
        self._pending: List[EvidenceBundle] = []

        self._genesis()

    # ----------------------------------------------------------------------- #
    # Genesis block
    # ----------------------------------------------------------------------- #

    def _genesis(self) -> None:
        """Create the initial genesis block."""

        genesis_root = MerkleTree(
            [_h(b"genesis")]
        ).root

        block = Block(
            index=0,
            ts=0.0,
            prev_hash="0" * 64,
            merkle_root=genesis_root,
            bundle_digests=[],
            sensor_id=self.sensor_id
        )

        block.signature = self._sign(block)

        self.blocks.append(block)

    # ----------------------------------------------------------------------- #
    # Signing
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
    # Adding evidence
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

        self._pending.append(bundle)

        if len(self._pending) >= self.batch_size:
            return self.seal(ts)

        return None

    # ----------------------------------------------------------------------- #
    # Sealing blocks
    # ----------------------------------------------------------------------- #

    def seal(
        self,
        ts: float
    ) -> Optional[Block]:
        """
        Close the current evidence batch into a signed,
        cryptographically linked block.
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
            sensor_id=self.sensor_id
        )

        block.signature = self._sign(block)

        self.blocks.append(block)

        self._pending = []

        return block

    # ----------------------------------------------------------------------- #
    # Merkle inclusion proofs
    # ----------------------------------------------------------------------- #

    def get_bundle_proof(
        self,
        block_index: int,
        bundle_index: int
    ) -> List[Tuple[str, str]]:
        """
        Generate an inclusion proof for a bundle digest
        stored inside a specific block.
        """

        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            raise IndexError("Invalid block index")

        block = self.blocks[block_index]

        if block_index == 0:
            raise IndexError(
                "Genesis block contains no evidence bundles"
            )

        if (
            bundle_index < 0
            or bundle_index >= len(block.bundle_digests)
        ):
            raise IndexError("Invalid bundle index")

        tree = MerkleTree(
            block.bundle_digests
        )

        return tree.proof(
            bundle_index
        )

    def bundle_proof(
        self,
        block_index: int,
        bundle_index: int
    ) -> dict:
        """
        Return a Merkle proof record using the project’s canonical API.
        """

        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            raise IndexError("Invalid block index")

        block = self.blocks[block_index]

        if block_index == 0:
            raise IndexError(
                "Genesis block contains no evidence bundles"
            )

        if (
            bundle_index < 0
            or bundle_index >= len(block.bundle_digests)
        ):
            raise IndexError("Invalid bundle index")

        proof = self.get_bundle_proof(
            block_index,
            bundle_index,
        )

        return {
            "block_index": block_index,
            "bundle_index": bundle_index,
            "bundle_digest": block.bundle_digests[bundle_index],
            "merkle_root": block.merkle_root,
            "proof": proof,
        }

    def verify_bundle_proof(
        self,
        *args,
        **kwargs,
    ) -> bool:
        """
        Verify a bundle proof.

        Accepts either:
            - ledger.verify_bundle_proof(block_index, bundle_digest, proof)
            - ledger.verify_bundle_proof(proof_record)
        """

        if len(args) == 1 and not kwargs:
            record = args[0]

            if not isinstance(record, dict):
                return False

            block_index = record.get("block_index")
            bundle_digest = record.get("bundle_digest")
            proof = record.get("proof")
            merkle_root = record.get("merkle_root")

            if (
                block_index is None
                or bundle_digest is None
                or proof is None
            ):
                return False

            if (
                block_index < 0
                or block_index >= len(self.blocks)
            ):
                return False

            if merkle_root is None:
                merkle_root = self.blocks[block_index].merkle_root

            return MerkleTree.verify_proof(
                bundle_digest,
                proof,
                merkle_root,
            )

        if len(args) == 3 and not kwargs:
            block_index, bundle_digest, proof = args
        elif "block_index" in kwargs:
            block_index = kwargs["block_index"]
            bundle_digest = kwargs["bundle_digest"]
            proof = kwargs["proof"]
        else:
            return False

        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            return False

        block = self.blocks[block_index]

        return MerkleTree.verify_proof(
            bundle_digest,
            proof,
            block.merkle_root,
        )

    # ----------------------------------------------------------------------- #
    # Block anchoring
    # ----------------------------------------------------------------------- #

    def anchor(
        self,
        block_index: int
    ) -> str:
        """
        Commit a block header to a stubbed permissioned ledger.

        In production this can be replaced with a real permissioned
        blockchain or external immutable ledger implementation.
        """

        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            raise IndexError("Invalid block index")

        block = self.blocks[block_index]

        reference = (
            "anchor://permissioned/"
            + block.header_hash()[:32]
        )

        block.anchored = True
        block.anchor_ref = reference

        return reference

    # ----------------------------------------------------------------------- #
    # Individual block verification
    # ----------------------------------------------------------------------- #

    def verify_block(
        self,
        block_index: int
    ) -> bool:
        """
        Verify a single block.

        Checks:
        - valid block index
        - correct Merkle root
        - correct previous-block linkage
        - valid sensor signature

        Returns True only if all checks pass.
        """

        # An invalid block cannot be valid. Return False instead of raising
        # so callers can safely treat verification as a boolean operation.
        if (
            block_index < 0
            or block_index >= len(self.blocks)
        ):
            return False

        block = self.blocks[block_index]

        # ------------------------------------------------------------------- #
        # Verify Merkle root
        # ------------------------------------------------------------------- #

        if block_index == 0:

            expected_root = MerkleTree(
                [_h(b"genesis")]
            ).root

        else:

            expected_root = MerkleTree(
                block.bundle_digests
            ).root

        if block.merkle_root != expected_root:
            return False

        # ------------------------------------------------------------------- #
        # Verify previous hash linkage
        # ------------------------------------------------------------------- #

        if block_index == 0:

            if block.prev_hash != "0" * 64:
                return False

        else:

            previous_block = self.blocks[
                block_index - 1
            ]

            if (
                block.prev_hash
                != previous_block.header_hash()
            ):
                return False

        # ------------------------------------------------------------------- #
        # Verify sensor signature
        # ------------------------------------------------------------------- #

        expected_signature = self._sign(
            block
        )

        if not hmac.compare_digest(
            block.signature,
            expected_signature
        ):
            return False

        return True

    # ----------------------------------------------------------------------- #
    # Complete chain verification
    # ----------------------------------------------------------------------- #

    def verify_chain(
        self
    ) -> Tuple[bool, Optional[int]]:
        """
        Verify every block in the evidence chain.

        Returns:
            (True, None)
                if the complete chain is intact.

            (False, block_index)
                if tampering is detected.
        """

        for index in range(
            len(self.blocks)
        ):

            if not self.verify_block(
                index
            ):
                return False, index

        return True, None

    # ----------------------------------------------------------------------- #
    # Persistent storage
    # ----------------------------------------------------------------------- #

    def to_dict(self) -> dict:
        """
        Convert the complete ledger state into a JSON-serializable dictionary.

        The signing key is intentionally NOT stored.
        """

        return {
            "storage_version": self.STORAGE_VERSION,
            "sensor_id": self.sensor_id,
            "batch_size": self.batch_size,

            "blocks": [
                asdict(block)
                for block in self.blocks
            ],

            "pending": [
                asdict(bundle)
                for bundle in self._pending
            ],
        }

    def save(
        self,
        path: str | Path
    ) -> Path:
        """
        Persist the ledger using an atomic write strategy.

        The ledger is written to a temporary file first and then atomically
        replaced. This helps avoid partially written ledger files.

        The signing key is never written to disk.
        """

        destination = Path(path)

        destination.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        fd, temp_path = tempfile.mkstemp(
            prefix=destination.name + ".",
            suffix=".tmp",
            dir=str(destination.parent)
        )

        try:

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.to_dict(),
                    file,
                    sort_keys=True,
                    separators=(",", ":"),
                    indent=2
                )

                file.flush()

                os.fsync(
                    file.fileno()
                )

            os.replace(
                temp_path,
                destination
            )

        except Exception:

            if os.path.exists(temp_path):
                os.remove(temp_path)

            raise

        return destination

    @classmethod
    def load(
        cls,
        path: str | Path,
        signing_key: bytes
    ) -> "EvidenceLedger":
        """
        Load a persisted ledger and immediately verify its integrity.

        The caller supplies the signing key because secret signing material is
        intentionally never stored in the persisted ledger.

        Raises:
            ValueError:
                If the persisted data is invalid or the ledger fails
                cryptographic verification.
        """

        source = Path(path)

        with source.open(
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )

        if not isinstance(
            data,
            dict
        ):
            raise ValueError(
                "Persisted ledger format is invalid"
            )

        if (
            data.get("storage_version")
            != cls.STORAGE_VERSION
        ):
            raise ValueError(
                "Unsupported ledger storage version"
            )

        sensor_id = data.get(
            "sensor_id"
        )

        batch_size = data.get(
            "batch_size"
        )

        blocks_data = data.get(
            "blocks"
        )

        pending_data = data.get(
            "pending",
            []
        )

        if (
            not isinstance(
                sensor_id,
                str
            )
            or not sensor_id
        ):
            raise ValueError(
                "Persisted ledger has an invalid sensor_id"
            )

        if (
            not isinstance(
                batch_size,
                int
            )
            or batch_size <= 0
        ):
            raise ValueError(
                "Persisted ledger has an invalid batch_size"
            )

        if not isinstance(
            blocks_data,
            list
        ):
            raise ValueError(
                "Persisted blocks are invalid"
            )

        if not isinstance(
            pending_data,
            list
        ):
            raise ValueError(
                "Persisted pending evidence is invalid"
            )

        ledger = cls(
            sensor_id=sensor_id,
            signing_key=signing_key,
            batch_size=batch_size
        )

        try:

            ledger.blocks = [
                Block(**block)
                for block in blocks_data
            ]

            ledger._pending = [
                EvidenceBundle(**bundle)
                for bundle in pending_data
            ]

        except (
            TypeError,
            KeyError
        ) as exc:

            raise ValueError(
                "Persisted ledger contains invalid "
                "block or evidence data"
            ) from exc

        if not ledger.blocks:
            raise ValueError(
                "Persisted ledger contains no blocks"
            )

        valid, broken_index = (
            ledger.verify_chain()
        )

        if not valid:

            raise ValueError(
                "Persisted evidence ledger failed verification "
                f"at block {broken_index}"
            )

        return ledger

    # ----------------------------------------------------------------------- #
    # Summary
    # ----------------------------------------------------------------------- #

    def summary(self) -> dict:
        """
        Return a concise summary of ledger state and integrity.
        """

        chain_ok, broken_index = (
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

            "first_broken_block": broken_index,

            "head": (
                self.blocks[-1]
                .header_hash()[:16]
                if self.blocks
                else None
            ),
        }