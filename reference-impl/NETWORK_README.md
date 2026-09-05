# Network Replay and Traffic Profiling

This contribution provides the CYCLOPS network ingestion layer around decoded PCAP traffic. It combines timestamp-preserving accelerated replay with traffic observability, input-quality reporting, replay controls, and progress reporting.

## Capabilities

- Replay PCAP packets at `1x`, `5x`, `10x`, or any positive speed multiplier.
- Preserve each packet's original `Packet.ts` value for downstream timing analysis.
- Measure packet count, byte count, TCP/UDP/DNS traffic, unique IPs, protocol distribution, and capture duration.
- Calculate packets-per-second and bytes-per-second rates.
- Divide traffic into configurable capture-time rate buckets for spike analysis.
- Report decoded-input quality, including malformed entries, unsupported entries, and missing timestamps.
- Pause, resume, or stop an active replay.
- Emit progress updates with packet count, capture timestamp, elapsed time, state, and completion fraction.
- Compare multiple captures using the same profiling schema.

The profiler reports network behavior. It does not classify threats; detector ownership remains in the existing HalfSight detector modules.

## Command-line monitor

From `reference-impl/`:

```bash
python -m halfsight.replay pcaps/benign.pcap --no-delay
python -m halfsight.replay pcaps/mixed.pcap --speed 10 --bucket 5
```

The command reports:

- packet and byte totals
- TCP, UDP, and DNS counts
- unique source and destination IPs
- capture and traffic rates
- capture duration and replay duration
- protocol distribution
- rate buckets
- decoded-input quality

Use `--no-delay` for maximum-speed offline profiling. Without it, packets are emitted using the original inter-packet delays divided by `--speed`.

## Python API

Profile a capture without replay delays:

```python
from halfsight.replay import profile_pcap

stats = profile_pcap("pcaps/mixed.pcap", bucket_seconds=1.0)
print(stats.packets_per_second)
print(stats.protocols)
print(stats.to_dict())
```

Feed replayed packets into the HalfSight pipeline:

```python
from halfsight.replay import replay_pcap

replay_pcap("pcaps/mixed.pcap", pipeline.ingest, speed=10)
```

Track replay progress:

```python
from halfsight.replay import PcapReplay


def on_progress(progress):
    print(progress.packets, progress.fraction, progress.state)


replay = PcapReplay(
    "pcaps/mixed.pcap",
    speed=10,
    progress_callback=on_progress,
)
for packet in replay.packets():
    pipeline.ingest(packet)
```

Controls can be called from another thread:

```python
replay.pause()
replay.resume()
replay.stop()
```

## Rate interpretation

Rate buckets use capture timestamps rather than wall-clock replay time. This means the same capture produces the same traffic profile at `1x` and `100x`; only delivery speed changes. A sudden increase in packet or byte rate is reported as an observation for the detection layer to interpret.

## Validation

The focused test suite covers:

- timestamp preservation and accelerated delay calculation
- non-monotonic timestamp handling
- no-delay mode
- packet consumer callbacks
- protocol, DNS, byte, IP, and rate statistics
- malformed decoded input accounting
- progress fractions and replay lifecycle state

Run it from `reference-impl/`:

```bash
python -m unittest discover -s tests -v
```
