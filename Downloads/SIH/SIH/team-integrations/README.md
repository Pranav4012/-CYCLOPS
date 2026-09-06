# Exact Team Integration Snapshots

This folder contains exact source snapshots copied from the teammate branches before compatibility integration.

## Included branches

| Snapshot | Branch | Role | Runtime status |
|---|---|---|---|
| `person1-engine/` | `person1-engine` | GHOSTFLOW, PULSE, VANTAGE, HalfSight inference | Preserved exactly; active runtime remains `reference-impl/halfsight`. |
| `detection/` | `detection` | SPECTER, BABEL, DGA, DNS tunnel, flood detectors | Preserved exactly; active runtime uses the existing pipeline contract. |
| `person-5-security/` | `person-5-security` | CALIBER, WIRESEAL, firewall, forensic evidence | Preserved exactly; backend exposes compatible evidence verification. |
| `develop/` | `develop` | Product artifacts and shared evaluation presentation | Preserved exactly; Person 6 frontend consumes live API data. |

The snapshots are intentionally isolated because the source branches use incompatible repository layouts. Their entire branch histories also contain unrelated deletions, so wholesale merges would damage the working CYCLOPS tree.

## Active concatenation

```text
Exact teammate snapshots
        -> compatibility registry
        -> existing reference-impl engine contract
        -> Person 2 backend API
        -> Person 6 frontend and tests
```

The active integration registry is available at `GET /api/integrations`.
