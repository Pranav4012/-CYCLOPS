"""Timestamp-aware PCAP replay and decoded network traffic profiling."""
from __future__ import annotations

import argparse
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, List, Optional, Tuple

from .pcap import read_pcap
from .types import Packet


@dataclass
class RateBucket:
    """Traffic observed in one capture-time interval."""

    start_s: float
    packets: int = 0
    bytes: int = 0

    @property
    def packets_per_second(self) -> float:
        return float(self.packets)


@dataclass
class NetworkTrafficStats:
    """Aggregate and time-bucketed statistics for decoded packets."""

    packets: int = 0
    bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    dns_packets: int = 0
    source_ips: set = field(default_factory=set)
    destination_ips: set = field(default_factory=set)
    protocols: Counter = field(default_factory=Counter)
    rate_buckets: List[RateBucket] = field(default_factory=list)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    valid_packets: int = 0
    malformed_packets: int = 0
    unsupported_packets: int = 0
    missing_timestamps: int = 0
    bucket_seconds: float = 1.0

    def add(self, packet: Packet) -> None:
        """Record one decoded packet without modifying it."""
        self.valid_packets += 1
        self.packets += 1
        self.bytes += max(0, packet.length)
        self.protocols[packet.proto.upper()] += 1
        if packet.proto.upper() == "TCP":
            self.tcp_packets += 1
        elif packet.proto.upper() == "UDP":
            self.udp_packets += 1
        if packet.dns_qname or packet.src_port == 53 or packet.dst_port == 53:
            self.dns_packets += 1
        self.source_ips.add(packet.src_ip)
        self.destination_ips.add(packet.dst_ip)

        if packet.ts is None:
            self.missing_timestamps += 1
            return
        if self.first_ts is None:
            self.first_ts = packet.ts
        self.last_ts = packet.ts
        offset = max(0.0, packet.ts - self.first_ts)
        bucket_index = int(offset // self.bucket_seconds)
        while len(self.rate_buckets) <= bucket_index:
            self.rate_buckets.append(RateBucket(
                self.first_ts + len(self.rate_buckets) * self.bucket_seconds))
        bucket = self.rate_buckets[bucket_index]
        bucket.packets += 1
        bucket.bytes += max(0, packet.length)

    @property
    def capture_duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def packets_per_second(self) -> float:
        return self.packets / self.capture_duration if self.capture_duration else 0.0

    @property
    def bytes_per_second(self) -> float:
        return self.bytes / self.capture_duration if self.capture_duration else 0.0

    @property
    def quality_percent(self) -> float:
        total = self.valid_packets + self.malformed_packets + self.unsupported_packets
        return 100.0 * self.valid_packets / total if total else 100.0

    @property
    def other_packets(self) -> int:
        return self.packets - self.tcp_packets - self.udp_packets

    def to_dict(self) -> dict:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "dns_packets": self.dns_packets,
            "unique_source_ips": len(self.source_ips),
            "unique_destination_ips": len(self.destination_ips),
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "capture_duration_s": self.capture_duration,
            "protocols": dict(self.protocols),
            "rate_buckets": [bucket.__dict__.copy() for bucket in self.rate_buckets],
            "valid_packets": self.valid_packets,
            "malformed_packets": self.malformed_packets,
            "unsupported_packets": self.unsupported_packets,
            "missing_timestamps": self.missing_timestamps,
            "quality_percent": self.quality_percent,
        }


class TrafficProfiler:
    """Profile a packet iterable; no threat classification is performed."""

    def __init__(self, bucket_seconds: float = 1.0):
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be greater than 0")
        self.bucket_seconds = bucket_seconds

    def profile(self, packets: Iterable[Packet]) -> NetworkTrafficStats:
        stats = NetworkTrafficStats(bucket_seconds=self.bucket_seconds)
        for packet in packets:
            if not isinstance(packet, Packet):
                stats.malformed_packets += 1
                continue
            stats.add(packet)
        return stats


@dataclass(frozen=True)
class ReplayProgress:
    packets: int
    total_packets: Optional[int]
    capture_ts: Optional[float]
    capture_duration: float
    elapsed: float
    speed: float
    state: str

    @property
    def fraction(self) -> Optional[float]:
        if not self.total_packets:
            return None
        return min(1.0, self.packets / self.total_packets)


class PcapReplay:
    """Yield captured packets with controllable wall-clock timing."""

    def __init__(
        self,
        path: str,
        speed: float = 1.0,
        backend: str = "auto",
        no_delay: bool = False,
        total_packets: Optional[int] = None,
        progress_callback: Optional[Callable[[ReplayProgress], None]] = None,
    ):
        if speed <= 0:
            raise ValueError("speed must be greater than 0")
        if total_packets is not None and total_packets < 0:
            raise ValueError("total_packets must not be negative")
        self.path = path
        self.speed = speed
        self.backend = backend
        self.no_delay = no_delay
        self.total_packets = total_packets
        self.progress_callback = progress_callback
        self.stats = NetworkTrafficStats()
        self._condition = threading.Condition()
        self._paused = False
        self._stopped = False
        self._state = "ready"

    def pause(self) -> None:
        with self._condition:
            if self._state in ("ready", "replaying"):
                self._paused = True
                self._state = "paused"

    def resume(self) -> None:
        with self._condition:
            self._paused = False
            if self._state == "paused":
                self._state = "replaying"
            self._condition.notify_all()

    def stop(self) -> None:
        with self._condition:
            self._stopped = True
            self._paused = False
            self._state = "stopped"
            self._condition.notify_all()

    @property
    def state(self) -> str:
        with self._condition:
            return self._state

    def _wait_until_running(self) -> bool:
        with self._condition:
            while self._paused and not self._stopped:
                self._condition.wait()
            return not self._stopped

    def _delay(self, delay: float) -> bool:
        if delay <= 0 or self.no_delay:
            return self._wait_until_running()
        if not self._wait_until_running():
            return False
        time.sleep(delay)
        return self._wait_until_running()

    def _progress(self, count: int, packet: Packet, started: float) -> None:
        if self.progress_callback is None:
            return
        self.progress_callback(ReplayProgress(
            count, self.total_packets, packet.ts, self.stats.capture_duration,
            time.monotonic() - started, self.speed, self.state))

    def packets(self) -> Iterator[Packet]:
        previous_ts: Optional[float] = None
        started = time.monotonic()
        count = 0
        with self._condition:
            if self._state == "ready":
                self._state = "replaying"

        for packet in read_pcap(self.path, backend=self.backend):
            if previous_ts is not None:
                capture_delay = max(0.0, packet.ts - previous_ts)
                if not self._delay(capture_delay / self.speed):
                    break
            elif not self._wait_until_running():
                break

            previous_ts = packet.ts
            self.stats.add(packet)
            count += 1
            self._progress(count, packet, started)
            yield packet

        with self._condition:
            if self._state != "stopped":
                self._state = "finished"


def profile_pcap(path: str, backend: str = "auto", bucket_seconds: float = 1.0) -> NetworkTrafficStats:
    """Profile decoded packets from a capture without replaying delays."""
    return TrafficProfiler(bucket_seconds).profile(read_pcap(path, backend=backend))


def compare_pcaps(paths: Iterable[Tuple[str, str]], backend: str = "auto") -> List[dict]:
    """Return compact, comparable profiles for ``(scenario, path)`` pairs."""
    rows = []
    for scenario, path in paths:
        stats = profile_pcap(path, backend=backend)
        rows.append({"scenario": scenario, **stats.to_dict()})
    return rows


def replay_pcap(
    path: str,
    consumer: Callable[[Packet], None],
    speed: float = 1.0,
    backend: str = "auto",
    no_delay: bool = False,
    progress_callback: Optional[Callable[[ReplayProgress], None]] = None,
) -> int:
    """Replay a capture into ``consumer`` and return the packet count."""
    replay = PcapReplay(path, speed, backend, no_delay,
                        progress_callback=progress_callback)
    for packet in replay.packets():
        consumer(packet)
    return replay.stats.packets


def _main() -> int:
    parser = argparse.ArgumentParser(description="Profile and replay a PCAP")
    parser.add_argument("path", help="classic PCAP or supported capture path")
    parser.add_argument("--speed", type=float, default=1.0)
    parser.add_argument("--backend", choices=("auto", "pure", "dpkt"), default="auto")
    parser.add_argument("--bucket", type=float, default=1.0,
                        help="capture-time rate bucket size in seconds")
    parser.add_argument("--no-delay", action="store_true")
    args = parser.parse_args()

    try:
        stats = profile_pcap(args.path, args.backend, args.bucket)
        replay = PcapReplay(args.path, args.speed, args.backend, args.no_delay,
                            total_packets=stats.packets)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    wall_start = time.monotonic()
    for _packet in replay.packets():
        pass
    replay_duration = time.monotonic() - wall_start
    print("CYCLOPS NETWORK MONITOR")
    print(f"Scenario: {args.path}")
    print(f"Packets: {stats.packets:,}    Traffic: {stats.bytes:,} bytes")
    print(f"TCP: {stats.tcp_packets:,}    UDP: {stats.udp_packets:,}    DNS: {stats.dns_packets:,}")
    print(f"Unique sources: {len(stats.source_ips):,}    Destinations: {len(stats.destination_ips):,}")
    print(f"Packet rate: {stats.packets_per_second:,.1f} pkt/s    Traffic rate: {stats.bytes_per_second:,.1f} B/s")
    print(f"Capture duration: {stats.capture_duration:.3f} sec")
    print(f"Replay: {'no-delay' if args.no_delay else f'{args.speed:g}x'} ({replay_duration:.3f} sec)")
    print(f"Input quality: {stats.quality_percent:.2f}% valid ({stats.malformed_packets} malformed, "
          f"{stats.unsupported_packets} unsupported, {stats.missing_timestamps} missing timestamps)")
    distribution = ", ".join(
        f"{name} {count / stats.packets * 100:.1f}%" for name, count in stats.protocols.items())
    print("Protocol distribution: " + (distribution or "no decoded packets"))
    print("Rate buckets:")
    for bucket in stats.rate_buckets:
        print(f"  {bucket.start_s - (stats.first_ts or 0):6.1f}-{bucket.start_s - (stats.first_ts or 0) + stats.bucket_seconds:6.1f}s "
              f"{bucket.packets_per_second:8.1f} pkt/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
def replay_pcap(
    path: str,
    consumer: Callable[[Packet], None],
    speed: float = 1.0,
    backend: str = "auto",
    no_delay: bool = False,
) -> int:
    """Replay a capture into ``consumer`` and return the packet count."""
    replay = PcapReplay(path, speed=speed, backend=backend, no_delay=no_delay)
    count = 0
    for packet in replay.packets():
        consumer(packet)
        count += 1
    return count


def _main() -> int:
    parser = argparse.ArgumentParser(description="Replay a PCAP at a controlled speed")
    parser.add_argument("path", help="classic PCAP or supported capture path")
    parser.add_argument("--speed", type=float, default=1.0,
                        help="replay speed multiplier (default: 1.0)")
    parser.add_argument("--backend", choices=("auto", "pure", "dpkt"), default="auto")
    parser.add_argument("--no-delay", action="store_true",
                        help="emit packets as fast as the reader allows")
    args = parser.parse_args()

    try:
        replay = PcapReplay(args.path, args.speed, args.backend, args.no_delay)
    except ValueError as exc:
        parser.error(str(exc))

    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    count = 0
    wall_start = time.monotonic()
    for packet in replay.packets():
        if first_ts is None:
            first_ts = packet.ts
        last_ts = packet.ts
        count += 1

    replay_duration = time.monotonic() - wall_start
    capture_span = max(0.0, (last_ts - first_ts) if first_ts is not None else 0.0)
    print("CYCLOPS PCAP REPLAY")
    print()
    print(f"File: {args.path}")
    print(f"Speed: {'no-delay' if args.no_delay else f'{args.speed:g}x'}")
    print()
    print(f"Packets replayed: {count}")
    print(f"Original span: {capture_span:.3f} sec")
    print(f"Replay duration: {replay_duration:.3f} sec")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())