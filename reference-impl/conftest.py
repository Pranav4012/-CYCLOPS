"""Ensure `halfsight` and `eval` import when pytest runs from reference-impl/."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
