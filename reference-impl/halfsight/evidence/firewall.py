"""Compatibility wrapper for the canonical firewall implementation.

The authoritative implementation lives at the package root so the project does
not contain conflicting firewall copies.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


_CANONICAL_PATH = Path(__file__).resolve().parents[1] / "firewall.py"

_spec = importlib.util.spec_from_file_location(
    "halfsight.firewall",
    _CANONICAL_PATH,
)

if _spec is None or _spec.loader is None:
    raise ImportError(f"Unable to load firewall from {_CANONICAL_PATH}")

_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

AdaptiveFirewall = _module.AdaptiveFirewall

__all__ = ["AdaptiveFirewall"]
