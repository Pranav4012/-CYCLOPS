"""types.py + halfflow.py — flow assembly, GHOSTFLOW reconstruction (incl. 32-bit
wrap), PULSE clock recovery (incl. TSval wrap + PAWS), VANTAGE role, liveness."""
from halfsight.types import Packet, UniFlow, FLAG_SYN, FLAG_ACK, FLAG_PSH, shannon_entropy
from halfsight.halfflow import HalfFlowReconstructor

hf = HalfFlowReconstructor()


def _tcp(ts, ack=None, tsval=None, flags=FLAG_ACK | FLAG_PSH, length=200):
    return Packet(ts, "10.0.0.1", "1.2.3.4", 5555, 443, "TCP", length,
                  tcp_flags=flags, tcp_ack=ack, tcp_tsval=tsval)


def test_uniflow_accumulates():
    f = UniFlow("10.0.0.1", "1.2.3.4", 5555, 443, "TCP")
    for k in range(5):
        f.update(_tcp(1000 + k * 0.1, ack=1000 + k * 500, length=100))
    assert f.packets == 5 and f.bytes == 500 and f.duration > 0
    assert f.ack_samples == 5


def test_shannon_entropy():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > shannon_entropy("aabb")


def test_reconstruct_reverse_bytes_basic():
    f = UniFlow("10.0.0.1", "1.2.3.4", 5555, 443, "TCP")
    isn = 1_000_000
    true_rev = 100_000
    n = 40
    for k in range(n):
        f.update(_tcp(1000 + k * 0.05, ack=isn + 1 + int(true_rev * k / (n - 1))))
    est, method, _ = hf.reconstruct_reverse_bytes(f)
    assert method == "ack-derivative"
    assert abs(est - true_rev) / true_rev < 0.05    # within 5%


def test_reconstruct_across_ack_wrap():
    f = UniFlow("10.0.0.1", "1.2.3.4", 5555, 443, "TCP")
    isn = (1 << 32) - 100_000            # ISN chosen so ACK crosses 2^32
    true_rev = 200_000
    n = 40
    for k in range(n):
        ack = (isn + 1 + int(true_rev * k / (n - 1))) & 0xFFFFFFFF
        f.update(_tcp(1000 + k * 0.05, ack=ack))
    est, method, _ = hf.reconstruct_reverse_bytes(f)
    assert f.ack_wraps == 1
    assert method == "ack-derivative"
    assert abs(est - true_rev) < 2       # exact modulo integer rounding


def test_ts_clock_recovery_and_wrap_paws():
    # clean 1000 Hz clock crossing 2^32, with one injected old/reordered TSval
    f = UniFlow("10.0.0.2", "1.2.3.4", 6000, 443, "TCP")
    base = (1 << 32) - 30_000
    for k in range(80):
        tsv = (base + k * 1000) & 0xFFFFFFFF
        f.update(_tcp(2000 + k * 1.0, ack=1000 + k, tsval=tsv, flags=FLAG_ACK))
        if k == 40:                       # inject a stale segment (PAWS should drop it)
            f.update(_tcp(2000 + k * 1.0 + 0.001, ack=1000 + k, tsval=(base) & 0xFFFFFFFF, flags=FLAG_ACK))
    hz, r2 = hf.recover_ts_clock(f)
    assert hz is not None and abs(hz - 1000.0) / 1000.0 < 0.02
    assert r2 > 0.99


def test_liveness_spoofed_vs_live():
    # spoofed SYN (no timestamps) -> low liveness
    spoof = UniFlow("198.18.0.1", "1.2.3.4", 40000, 80, "TCP")
    spoof.update(Packet(1.0, "198.18.0.1", "1.2.3.4", 40000, 80, "TCP", 60, tcp_flags=FLAG_SYN))
    assert hf.estimate(spoof).liveness_score < 0.5
    # live host with coherent TCP-timestamp clock -> high liveness
    live = UniFlow("10.0.0.9", "1.2.3.4", 50000, 443, "TCP")
    for k in range(12):
        live.update(_tcp(k * 0.05, ack=1000 + k * 400, tsval=100000 + int(k * 0.05 * 1000)))
    assert hf.estimate(live).liveness_score > 0.8
