import unittest
from unittest.mock import patch

from halfsight.replay import PcapReplay, TrafficProfiler, replay_pcap
from halfsight.types import Packet


def packet(ts):
    return Packet(ts, "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 10)


def udp_packet(ts, dns=False):
    return Packet(ts, "10.0.0.3", "8.8.8.8", 53000, 53 if dns else 443,
                  "UDP", 20, dns_qname="example.com" if dns else None)


class PcapReplayTests(unittest.TestCase):
    @patch("halfsight.replay.read_pcap")
    @patch("halfsight.replay.time.sleep")
    def test_scales_delays_without_changing_timestamps(self, sleep, read_pcap):
        packets = [packet(0.0), packet(1.0), packet(2.0)]
        read_pcap.return_value = iter(packets)

        result = list(PcapReplay("capture.pcap", speed=10).packets())

        self.assertEqual(result, packets)
        sleep.assert_has_calls([unittest.mock.call(0.1), unittest.mock.call(0.1)])

    @patch("halfsight.replay.read_pcap")
    @patch("halfsight.replay.time.sleep")
    def test_clamps_non_monotonic_timestamps(self, sleep, read_pcap):
        read_pcap.return_value = iter([packet(2.0), packet(1.0), packet(3.0)])

        list(PcapReplay("capture.pcap").packets())

        sleep.assert_called_once_with(2.0)

    @patch("halfsight.replay.read_pcap")
    @patch("halfsight.replay.time.sleep")
    def test_no_delay_skips_sleep(self, sleep, read_pcap):
        read_pcap.return_value = iter([packet(0.0), packet(1.0)])

        list(PcapReplay("capture.pcap", no_delay=True).packets())

        sleep.assert_not_called()

    @patch("halfsight.replay.read_pcap")
    def test_consumer_helper_returns_count(self, read_pcap):
        packets = [packet(0.0), packet(0.1)]
        read_pcap.return_value = iter(packets)
        received = []

        count = replay_pcap("capture.pcap", received.append, no_delay=True)

        self.assertEqual(count, 2)
        self.assertEqual(received, packets)

    def test_speed_must_be_positive(self):
        with self.assertRaises(ValueError):
            PcapReplay("capture.pcap", speed=0)
        with self.assertRaises(ValueError):
            PcapReplay("capture.pcap", speed=-1)

    def test_profiles_protocols_rates_and_quality(self):
        stats = TrafficProfiler().profile([
            packet(10.0), udp_packet(10.2, dns=True), udp_packet(11.1), "malformed"
        ])

        self.assertEqual(stats.packets, 3)
        self.assertEqual(stats.bytes, 50)
        self.assertEqual(stats.tcp_packets, 1)
        self.assertEqual(stats.udp_packets, 2)
        self.assertEqual(stats.dns_packets, 1)
        self.assertEqual(len(stats.source_ips), 2)
        self.assertEqual(len(stats.destination_ips), 2)
        self.assertEqual([bucket.packets for bucket in stats.rate_buckets], [2, 1])
        self.assertEqual(stats.malformed_packets, 1)
        self.assertAlmostEqual(stats.quality_percent, 75.0)

    @patch("halfsight.replay.read_pcap")
    @patch("halfsight.replay.time.sleep")
    def test_progress_and_lifecycle(self, sleep, read_pcap):
        progress = []
        read_pcap.return_value = iter([packet(0.0), packet(1.0)])
        replay = PcapReplay("capture.pcap", no_delay=True, total_packets=2,
                            progress_callback=progress.append)

        replay.pause()
        self.assertEqual(replay.state, "paused")
        replay.resume()
        self.assertEqual(replay.state, "replaying")
        self.assertEqual(len(list(replay.packets())), 2)
        self.assertEqual(replay.state, "finished")
        self.assertEqual([item.fraction for item in progress], [0.5, 1.0])
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()