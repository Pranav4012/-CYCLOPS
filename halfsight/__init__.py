"""
halfsight — a unidirectional-first passive threat-detection reference core.

Public surface:
    from halfsight import Pipeline, FlowTable, Packet
    from halfsight.halfflow import HalfFlowReconstructor
"""
from .types import Packet, UniFlow, Alert
from .pipeline import Pipeline, FlowTable

__all__ = ["Packet", "UniFlow", "Alert", "Pipeline", "FlowTable"]
__version__ = "0.3.1"
