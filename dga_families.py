from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class DGAFamily:
    name: str
    description: str
    length_range: tuple[int, int]      # (min, max) domain label length
    charset_pattern: str                # regex the label must fully match
    common_tlds: set[str]                # TLDs this family favors, empty = any


DGA_FAMILIES: list[DGAFamily] = [
    DGAFamily(
        name="conficker-like",
        description="Fixed-length pseudo-random alphanumeric, no vowels bias",
        length_range=(8, 11),
        charset_pattern=r"^[a-z0-9]+$",
        common_tlds={"com", "net", "org", "info", "biz"},
    ),
    DGAFamily(
        name="cryptolocker-like",
        description="12-character pure-lowercase pseudo-random domains",
        length_range=(12, 12),
        charset_pattern=r"^[a-z]+$",
        common_tlds={"com", "net", "ru", "biz"},
    ),
    DGAFamily(
        name="necurs-like",
        description="Longer random alphanumeric with digit-heavy labels",
        length_range=(16, 24),
        charset_pattern=r"^[a-z0-9]+$",
        common_tlds=set(),  # no strong TLD preference
    ),
    DGAFamily(
        name="suppobox-like",
        description="Two concatenated dictionary words (harder to catch on entropy alone)",
        length_range=(10, 20),
        charset_pattern=r"^[a-z]+$",
        common_tlds={"com", "net"},
    ),
]


def match_family(label: str, tld: str | None = None) -> DGAFamily | None:
    """
    Returns the first DGAFamily whose length/charset/TLD profile matches
    this label, or None if it doesn't fit any known family. A match here
    is a strong signal — combine with (not replace) the entropy score in
    babel.py rather than using this alone, since suppobox-like domains
    deliberately evade entropy-based detection.
    """
    length = len(label)
    for family in DGA_FAMILIES:
        if not (family.length_range[0] <= length <= family.length_range[1]):
            continue
        if not re.match(family.charset_pattern, label):
            continue
        if family.common_tlds and tld and tld.lower() not in family.common_tlds:
            continue
        return family
    return None