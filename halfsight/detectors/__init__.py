from .beaconing import SpectralBeaconDetector
from .dga import DGAClassifier
from .dns_tunnel import DNSTunnelDetector
from .floods import FloodSlowlorisDetector

__all__ = [
    "SpectralBeaconDetector", "DGAClassifier",
    "DNSTunnelDetector", "FloodSlowlorisDetector",
]
