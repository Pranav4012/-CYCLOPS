"""Registry for the exact teammate snapshots used by the Person 6 build."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "team-integrations"

TEAM_INTEGRATIONS = {
    "person1_engine": {
        "branch": "person1-engine",
        "path": "team-integrations/person1-engine/halfsight",
        "role": "GHOSTFLOW, PULSE, VANTAGE, and HalfSight inference",
        "active_adapter": "reference-impl/halfsight remains the runtime engine",
    },
    "detection": {
        "branch": "detection",
        "path": "team-integrations/detection/halfsight",
        "role": "SPECTER, BABEL, DGA, DNS tunnel, flood detectors",
        "active_adapter": "backend consumes the existing reference-impl Pipeline contract",
    },
    "person5_security": {
        "branch": "person-5-security",
        "path": "team-integrations/person-5-security/reference-impl",
        "role": "CALIBER, WIRESEAL, firewall, and forensic evidence",
        "active_adapter": "backend exposes WIRESEAL records and verification APIs",
    },
    "develop": {
        "branch": "develop",
        "path": "team-integrations/develop/product",
        "role": "shared CYCLOPS product artifacts and evaluation presentation",
        "active_adapter": "frontend consumes live backend results instead of scripted data",
    },
}


def integration_status() -> dict:
    return {
        name: {**details, "snapshot_present": (ROOT / details["path"].removeprefix("team-integrations/")).exists()}
        for name, details in TEAM_INTEGRATIONS.items()
    }
