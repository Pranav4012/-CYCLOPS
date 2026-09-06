# CYCLOPS - Detection

Person 3 owns three threat detectors for the CYCLOPS SIH26145 pipeline:

- **SPECTER**: detects botnet command-and-control beaconing.
- **BABEL**: detects DGA domains and DNS tunnelling.
- **FLOODS**: detects volumetric and protocol DDoS traffic.

The detectors are independent of packet capture and flow ingestion. They
accept prepared Flow dictionaries and return Alert dictionaries for the
shared alert pipeline.

## Detection Modules

| Codename | Module | Detection method | Alert class |
| --- | --- | --- | --- |
| SPECTER | `reference-impl/halfsight/detectors/beaconing.py` | Rayleigh periodogram, interval regularity, and payload-size regularity | `c2_beaconing` |
| BABEL | `reference-impl/halfsight/detectors/dga.py` | DGA lexical scoring with entropy, n-grams, and model support | `dga_domain` |
| BABEL | `reference-impl/halfsight/detectors/dns_tunnel.py` | DNS query volume, entropy, uniqueness, and qtype analysis | `dns_tunnelling` |
| FLOODS | `reference-impl/halfsight/detectors/floods.py` | SYN/UDP rate, source-IP entropy, reflection, and Slowloris analysis | `syn_flood`, `reflection_amplification` |

Supporting modules:

- `dga_families.py` contains explainable DGA family profiles.
- `dga_model.py` loads an optional `dga_model.npz` NumPy model when present.

## Flow Input

The upstream ingest layer should normalize data into dictionaries with the
fields required by the detector being called.

```python
{
    "flow_id": "flow-001",
    "timestamp": "2026-01-01T00:01:00+00:00",
    "src_ip": "10.0.0.10",
    "dst_ip": "8.8.8.8",
    "packet_count": 120,
    "byte_count": 9600,
    "dns_query": {"qname": "example.com"},
}
```

Grouping is performed by the caller:

- SPECTER expects `{(src_ip, dst_ip): [flow, ...]}`.
- FLOODS expects `{dst_ip: [flow, ...]}` for one analysis window.
- BABEL expects a list of flows containing DNS queries.

## Usage

```python
from halfsight.detectors import babel, floods, spector

alerts = []
alerts.extend(spector.detect(flows_by_pair))
alerts.extend(babel.detect(flows_with_dns))
alerts.extend(floods.detect(flows_by_destination, window_seconds=1.0))
```

Every generated alert contains these shared fields:

```text
timestamp, flow_id, threat_class, confidence, severity,
src_ip, dst_ip, evidence, detector
```

`confidence` is a number from `0` to `1`. `evidence` contains the measurements
that caused the alert, such as beacon score, DNS entropy, query length, packet
rate, byte rate, or source-IP entropy.

## Setup

Use the repository virtual environment when available:

```powershell
\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The runtime requires NumPy. Pytest is included for local validation.

## Tests

Run the focused Person 3 test suite from the repository root:

```powershell
python -m pytest tests/test_detection.py -v
```

The tests cover regular and irregular beaconing, DGA and normal DNS, DNS
tunnelling, volumetric floods, invalid flood windows, and the shared Alert
fields.

## Thresholds

Thresholds are constants at the top of each detector and should be tuned with
representative replay traffic:

- SPECTER: `BEACON_CV_THRESHOLD`, `BEACON_MIN_SAMPLES`, and
  `BEACON_MIN_INTERVAL_SEC`.
- BABEL: `ENTROPY_THRESHOLD`, `QUERY_LEN_THRESHOLD`, and
  `TUNNEL_QUERY_RATE_THRESHOLD`.
- FLOODS: `PACKET_RATE_THRESHOLD`, `BYTE_RATE_THRESHOLD`, and
  `MIN_FLOWS_FOR_JUDGEMENT`.

## Integration Boundary

Person 3 does not own PCAP parsing, streaming, flow reconstruction, API or
WebSocket delivery, confidence calibration, evidence integrity, or the SOC
interface. Those responsibilities belong to the other team modules.

Before production use, connect these detectors to the ingest pipeline and
validate them against representative PCAPs. BABEL should gain an
environment-specific allowlist and stronger family signatures to reduce false
positives on legitimate domains.
