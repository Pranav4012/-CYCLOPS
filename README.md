# detection — CYCLOPS detection modules

This branch implements three of the CYCLOPS pipeline's detection modules:
**SPECTER** (C2 beaconing), **BABEL** (DGA/DNS tunnelling), and
**BACKLOG ORACLE** (flood/DoS). It plugs into the shared SIH26145 pipeline
between feature extraction and the API/alert layer.

## Scope of this branch

| Module | File | Detects | Output threat_class |
|---|---|---|---|
| SPECTER | `specter.py` | C2 beaconing via inter-arrival regularity | `botnet_c2_beaconing` |
| BABEL | `babel.py` | DGA domains + DNS tunnelling via entropy/n-gram scoring | `dga_dns_tunnelling` |
| BACKLOG ORACLE | `backlog_oracle.py` | Volumetric floods via rate + source-IP entropy | `volumetric_ddos` |

`pipeline.py` is the single entry point — it groups incoming flows the way
each module needs and returns the combined alert list.

**Out of scope for this branch:** GHOSTFLOW, PULSE, VANTAGE, CALIBER,
WIRESEAL, and the recon/scanning + exfiltration + encrypted-malware
detectors — those live on other branches.

## Folder structure (this branch's part of the repo)

```
backend/
├── src/sih_detector/detection/
│   ├── specter.py         SPECTER — C2 beaconing
│   ├── babel.py            BABEL — DGA / DNS tunnelling
│   ├── backlog_oracle.py   BACKLOG ORACLE — flood/DoS
│   ├── pipeline.py         orchestrator: run_detectors(flows)
│   └── README.md           module-level notes and thresholds
└── tests/
    └── test_detection.py   unit tests for all three modules
```

## Input / output contract

Input: a list of Flow dicts matching `schemas/flow.schema.json`.
Output: a list of Alert dicts matching `schemas/alert.schema.json`.

```python
from sih_detector.detection.pipeline import run_detectors

alerts = run_detectors(flows, window_seconds=1.0)
```

Nothing on this branch depends on real ingest or feature-extraction code —
the detectors consume Flow dicts directly, so this branch can be developed
and tested fully in isolation against synthetic/mock data.

## Running the tests

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/test_detection.py -v
```

8 tests, all passing as of the last commit on this branch — covering a
regular-beacon case and a bursty/irregular case for SPECTER, a DGA-entropy
case, a normal-domain case, and a high-query-rate tunnelling case for
BABEL, a flood case and a normal-traffic case for BACKLOG ORACLE, and one
end-to-end pipeline test combining all three.

## Tuning thresholds

Each module keeps its thresholds as constants at the top of the file —
tune these against real replayed traffic instead of the synthetic test
data if detections look too sensitive or not sensitive enough:

- `specter.py`: `BEACON_CV_THRESHOLD`, `BEACON_MIN_INTERVAL_SEC`
- `babel.py`: `ENTROPY_THRESHOLD`, `QUERY_LEN_THRESHOLD`, `TUNNEL_QUERY_RATE_THRESHOLD`
- `backlog_oracle.py`: `PACKET_RATE_THRESHOLD`, `BYTE_RATE_THRESHOLD`, `SRC_ENTROPY_SPOOF_THRESHOLD`

## Merging into main

This branch only touches files under `backend/src/sih_detector/detection/`
and `backend/tests/test_detection.py` — no shared schemas were modified,
so it should merge cleanly. Merge after the ingest/features branches so
`pipeline.run_detectors()` can be wired to real flow data instead of mocks.

## If there's time left

- Replace SPECTER's coefficient-of-variation check with autocorrelation/FFT
  for beacon detection robust to jittered malware timing.
- Add a calibration pass (CALIBER) to rescale confidence scores from all
  three modules onto one consistent probability scale before they reach
  the API.
