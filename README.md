# Detection — CYCLOPS modules

This branch implements three CYCLOPS detection modules: **SPECTER** (C2
beaconing), **BABEL** (DGA/DNS tunnelling), and **FLOODS** (volumetric DDoS).
The modules consume Flow dictionaries and return Alert dictionaries for the
shared pipeline.

## Scope of this branch

| Module | File | Detects | Output threat_class |
|---|---|---|---|
| SPECTER | `specter.py` | C2 beaconing via inter-arrival regularity | `botnet_c2_beaconing` |
| BABEL | `babel.py` | DGA domains + DNS tunnelling via entropy/n-gram scoring | `dga_dns_tunnelling` |
| FLOODS | `floods.py` | Volumetric floods via rate + source-IP entropy | `volumetric_ddos` |

**Out of scope for this branch:** GHOSTFLOW, PULSE, VANTAGE, CALIBER,
WIRESEAL, and the recon/scanning + exfiltration + encrypted-malware
detectors — those live on other branches.

## Folder structure
```
dga_families.py             known DGA family signatures
dga_model.py                optional NumPy model scoring
halfsight/detectors/
├── specter.py              SPECTER — C2 beaconing
├── babel.py                BABEL — DGA / DNS tunnelling
└── floods.py               FLOODS — volumetric DDoS
tests/test_detection.py     focused detector tests
requirements.txt            runtime and test dependencies
```
```

## Input / output contract

Input: a list of Flow dicts matching `schemas/flow.schema.json`.
Output: a list of Alert dicts matching `schemas/alert.schema.json`.

```python
from halfsight.detectors import babel, floods, spector

alerts = []
alerts.extend(babel.detect(dns_flows))
alerts.extend(floods.detect(flows_by_destination, window_seconds=1.0))
alerts.extend(spector.detect(flows_by_pair))
```

Nothing on this branch depends on real ingest or feature-extraction code —
the detectors consume Flow dicts directly, so this branch can be developed
and tested fully in isolation against synthetic/mock data.

## Running the tests

```bash
python -m pip install -r requirements.txt
python -m pytest tests/test_detection.py -v
```

The focused suite covers regular and irregular beaconing, DGA and normal DNS,
DNS tunnelling, volumetric floods, invalid flood windows, and the shared Alert
fields. Real PCAP replay and pipeline integration remain required before
production deployment.

## Tuning thresholds

Each module keeps its thresholds as constants at the top of the file —
tune these against real replayed traffic instead of the synthetic test
data if detections look too sensitive or not sensitive enough:

- `specter.py`: `BEACON_CV_THRESHOLD`, `BEACON_MIN_INTERVAL_SEC`
- `babel.py`: `ENTROPY_THRESHOLD`, `QUERY_LEN_THRESHOLD`, `TUNNEL_QUERY_RATE_THRESHOLD`
- `floods.py`: `PACKET_RATE_THRESHOLD`, `BYTE_RATE_THRESHOLD`

## Merging into main

No shared schemas are modified. Wire these detectors to the ingest/feature
pipeline after those branches are available, then replay representative PCAPs
to tune thresholds and measure false positives.

## If there's time left

- Replace SPECTER's coefficient-of-variation check with autocorrelation/FFT
  for beacon detection robust to jittered malware timing.
- Add a calibration pass (CALIBER) to rescale confidence scores from all
  three modules onto one consistent probability scale before they reach
  the API.
