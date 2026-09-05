"""SPECTER (beaconing), BABEL (DGA + DNS tunnel) detector unit tests."""
import random

from halfsight.detectors.beaconing import SpectralBeaconDetector
from halfsight.detectors.dga import DGAClassifier
from halfsight.detectors.dns_tunnel import DNSTunnelDetector


# ---- SPECTER --------------------------------------------------------------
def test_specter_detects_periodic():
    det = SpectralBeaconDetector()
    events = [i * 60.0 for i in range(15)]           # perfect 60s beacon
    r = det.analyze(events, [512] * 15)
    assert r.is_beacon and abs(r.period_s - 60.0) < 1.0


def test_specter_rejects_aperiodic():
    """Look-elsewhere correction: Poisson traffic must NOT read as a beacon."""
    det = SpectralBeaconDetector()
    rng = random.Random(0)
    fp = 0
    for _ in range(50):
        ev, t = [], 0.0
        for _ in range(15):
            t += rng.expovariate(1 / 60.0); ev.append(t)
        if det.analyze(ev, [512] * 15).is_beacon:
            fp += 1
    assert fp / 50 <= 0.05                            # <=5% false-beacon rate


def test_specter_too_few_events():
    assert not SpectralBeaconDetector().analyze([0, 60, 120], [512] * 3).is_beacon


# ---- BABEL / DGA ----------------------------------------------------------
def test_dga_model_loads_and_flags():
    clf = DGAClassifier()
    assert clf.model is not None                      # committed dga_model.npz loads
    rng = random.Random(1)
    dga = ["".join(rng.choice("abcdefghijklmnop0123456789") for _ in range(16)) + ".info"
           for _ in range(30)]
    assert sum(clf.score(d).is_dga for d in dga) / len(dga) > 0.5


def test_dga_benign_clean():
    clf = DGAClassifier()
    for d in ["google.com", "github.com", "wikipedia.org", "cloudflare.com", "windowsupdate.com"]:
        assert not clf.score(d).is_dga


def test_dga_heuristic_fallback():
    clf = DGAClassifier(use_model=False)              # force the hand-tuned path
    assert clf.model is None
    assert clf.score("xk4mz9qp2vw7bnrt.info").is_dga
    assert not clf.score("google.com").is_dga


# ---- BABEL / DNS tunnel ---------------------------------------------------
def test_dns_tunnel_detects():
    det = DNSTunnelDetector()
    rng = random.Random(2)
    dom = "tunnel-c2.net"
    qn = ["".join(rng.choice("abcdefghijklmnop234567") for _ in range(30)) + "." + dom
          for _ in range(40)]
    r = det.analyze(dom, qn, ["TXT"] * len(qn), window_s=30.0)
    assert r.is_tunnel


def test_dns_tunnel_benign_cdn_clean():
    det = DNSTunnelDetector()
    rng = random.Random(3)
    names = [f"{p}-{rng.randint(0, 40)}" for p in ("img", "static", "cache", "edge")]
    qn = [rng.choice(names) + ".akamai-cdn.net" for _ in range(45)]
    assert not det.analyze("akamai-cdn.net", qn, ["A"] * len(qn), window_s=30.0).is_tunnel


def test_dns_tunnel_too_few_queries():
    det = DNSTunnelDetector()
    assert not det.analyze("x.net", ["abc.x.net"] * 5, ["A"] * 5, window_s=30.0).is_tunnel
