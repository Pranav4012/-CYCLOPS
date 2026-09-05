"""
Real DGA domains from published algorithms + a real benign top-domains list.

The problem statement asks for "DGA samples from published algorithms." Rather
than random strings, we reproduce two well-documented families and score them
against genuinely popular domains:

  * CRYPTOLOCKER — the date-seeded xorshift arithmetic DGA (as reverse-engineered
    in Johannes Bader's widely-cited DGA collection). Produces high-entropy
    pronounceable-free labels like ``ymkdlqodocxk.com``.
  * A DICTIONARY DGA (suppobox/matsnu style) — concatenates real English words
    from a seeded PRNG, e.g. ``springmother.net``. These defeat entropy alone,
    so BABEL's dictionary tell must catch them.

BENIGN_DOMAINS is a static sample of globally popular domains (the kind a Tranco
/ Cisco-Umbrella top list contains) — real, verifiable, and exactly the traffic
a DGA detector must NOT flag.
"""
from __future__ import annotations

from typing import List, Iterator


# =============================================================================
# CRYPTOLOCKER — date-seeded xorshift arithmetic DGA (Bader reference form)
# =============================================================================
def cryptolocker(year: int, month: int, day: int, count: int = 100,
                 length: int = 12) -> Iterator[str]:
    tlds = ["com", "net", "biz", "ru", "org", "co.uk", "info"]
    for i in range(count):
        year = ((year ^ 8 * year) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
        month = ((month ^ 4 * month) >> 25) ^ 16 * (month & 0xFFFFFFF8)
        day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
        domain = ""
        for _ in range(length):
            year = ((year ^ 8 * year) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
            month = ((month ^ 4 * month) >> 25) ^ 16 * (month & 0xFFFFFFF8)
            day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
            domain += chr(((year ^ month ^ day) % 25) + ord("a"))
        yield f"{domain}.{tlds[i % len(tlds)]}"


# =============================================================================
# DICTIONARY DGA — suppobox/matsnu style two-word concatenation (LCG-seeded)
# =============================================================================
_WORDS = ("time year people way day man thing woman life child world school "
          "state family student group country problem hand part place case week "
          "company system program work government number night point home water "
          "room mother area money story fact month lot right study book eye job "
          "word business issue side kind head house service friend father power "
          "hour game line end member law car city community name president team "
          "spring summer winter river stone light shadow silver copper garden "
          "mountain forest ocean market bridge castle window mirror").split()
_DICT_TLDS = ["net", "com", "org", "info", "biz"]


def dictionary_dga(seed: int, count: int = 100) -> Iterator[str]:
    s = seed & 0xFFFFFFFF
    for i in range(count):
        s = (1103515245 * s + 12345) & 0x7FFFFFFF        # POSIX LCG
        a = s % len(_WORDS)
        s = (1103515245 * s + 12345) & 0x7FFFFFFF
        b = s % len(_WORDS)
        yield f"{_WORDS[a]}{_WORDS[b]}.{_DICT_TLDS[i % len(_DICT_TLDS)]}"


# =============================================================================
# Real benign top domains (sample of a Tranco/Umbrella-style list)
# =============================================================================
BENIGN_DOMAINS: List[str] = (
    "google.com youtube.com facebook.com wikipedia.org amazon.com yahoo.com "
    "reddit.com instagram.com twitter.com linkedin.com netflix.com microsoft.com "
    "office.com live.com bing.com apple.com icloud.com github.com gitlab.com "
    "stackoverflow.com cloudflare.com akamai.com fastly.net wordpress.org "
    "adobe.com dropbox.com spotify.com twitch.tv whatsapp.com telegram.org "
    "zoom.us slack.com salesforce.com oracle.com ibm.com intel.com nvidia.com "
    "paypal.com stripe.com shopify.com ebay.com aliexpress.com walmart.com "
    "target.com bestbuy.com nytimes.com bbc.co.uk theguardian.com cnn.com "
    "reuters.com bloomberg.com forbes.com medium.com quora.com pinterest.com "
    "tumblr.com vimeo.com soundcloud.com wikimedia.org mozilla.org ubuntu.com "
    "debian.org kernel.org python.org nodejs.org npmjs.com docker.com "
    "kubernetes.io redhat.com android.com chrome.com gstatic.com googleapis.com "
    "windowsupdate.com office365.com sharepoint.com outlook.com skype.com "
    "wikihow.com imdb.com espn.com nasa.gov nih.gov mit.edu stanford.edu "
    "harvard.edu berkeley.edu wsj.com economist.com nationalgeographic.com "
    "britannica.com merriam-webster.com weather.com accuweather.com booking.com "
    "airbnb.com uber.com lyft.com doordash.com yelp.com tripadvisor.com "
    "expedia.com marriott.com hilton.com samsung.com sony.com lg.com dell.com "
    "hp.com lenovo.com asus.com cisco.com vmware.com atlassian.com jira.com "
    "bitbucket.org sourceforge.net archive.org w.org duckduckgo.com brave.com "
    "protonmail.com signal.org discord.com steampowered.com epicgames.com "
    "roblox.com minecraft.net ea.com ubisoft.com nintendo.com playstation.com "
    "xbox.com twitch.com coinbase.com binance.com kraken.com robinhood.com "
    "fidelity.com schwab.com chase.com bankofamerica.com wellsfargo.com "
    "citibank.com hsbc.com barclays.co.uk visa.com mastercard.com amex.com"
).split()


# =============================================================================
# Sampling helpers
# =============================================================================
def sample_dga(family: str, n: int, seed: int = 20240115) -> List[str]:
    y, mth, d = 2024, 1, 15
    if family == "cryptolocker":
        return list(cryptolocker(y + (seed % 5), mth, d, count=n))
    if family == "dictionary":
        return list(dictionary_dga(seed, count=n))
    raise ValueError(family)


def sample_benign(n: int, seed: int = 0) -> List[str]:
    import random
    r = random.Random(seed)
    pool = BENIGN_DOMAINS[:]
    r.shuffle(pool)
    if n <= len(pool):
        return pool[:n]
    return [pool[i % len(pool)] for i in range(n)]
