"""
Adaptive Firewall Module
========================

Provides a simple adaptive firewall implementation with:

- Threat classification
- Allowlist support
- Permanent blocking
- Temporary blocking
- Rule expiration
- Event logging
- Firewall statistics
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional


# ============================================================
# TEMPORARY RULE
# ============================================================

@dataclass
class TemporaryRule:
    source: str
    created_at: float
    expires_at: float
    reason: str = ""


# ============================================================
# ADAPTIVE FIREWALL
# ============================================================

class AdaptiveFirewall:
    """
    Adaptive firewall implementation.

    Threat levels:

        0.00 - 0.09 -> MINIMAL
        0.10 - 0.49 -> LOW
        0.50 - 0.74 -> MEDIUM
        0.75 - 0.89 -> HIGH
        0.90 - 1.00 -> CRITICAL
    """

    # --------------------------------------------------------
    # THREAT LEVEL CONSTANTS
    # --------------------------------------------------------

    LOW_THREAT = 0.10
    MEDIUM_THREAT = 0.50
    HIGH_THREAT = 0.75
    CRITICAL_THREAT = 0.90

    # --------------------------------------------------------
    # INITIALIZATION
    # --------------------------------------------------------

    def __init__(self) -> None:
        """
        Initialize the firewall.
        """

        # Sources that are always allowed.
        self.allowlisted_sources: set[str] = set()

        # Permanently blocked sources.
        self.blocked_sources: set[str] = set()

        # Temporary firewall rules.
        self.temporary_rules: Dict[str, TemporaryRule] = {}

        # Event log.
        self.events: List[dict] = []

        # Statistics.
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0

    # ========================================================
    # EVENT LOGGING
    # ========================================================

    def _log_event(
        self,
        event_type: str,
        source: str,
        details: Optional[dict] = None,
    ) -> None:
        """
        Record an event.
        """

        event = {
            "timestamp": time.time(),
            "type": event_type,
            "source": source,
            "details": details or {},
        }

        self.events.append(event)

    # ========================================================
    # THREAT CLASSIFICATION
    # ========================================================

    def classify_threat(self, threat_level: float) -> str:
        """
        Classify a numeric threat level.

        Parameters
        ----------
        threat_level : float
            A value between 0.0 and 1.0.

        Returns
        -------
        str
            MINIMAL, LOW, MEDIUM, HIGH, or CRITICAL.
        """

        if not isinstance(threat_level, (int, float)):
            raise TypeError(
                "threat_level must be numeric"
            )

        threat_level = float(threat_level)

        if threat_level < 0.0 or threat_level > 1.0:
            raise ValueError(
                "threat_level must be between 0.0 and 1.0"
            )

        # Highest threat first.

        if threat_level >= self.CRITICAL_THREAT:
            return "CRITICAL"

        if threat_level >= self.HIGH_THREAT:
            return "HIGH"

        if threat_level >= self.MEDIUM_THREAT:
            return "MEDIUM"

        if threat_level >= self.LOW_THREAT:
            return "LOW"

        return "MINIMAL"

    # ========================================================
    # ALLOWLIST
    # ========================================================

    def add_to_allowlist(self, source: str) -> None:
        """
        Add a source to the allowlist.
        """

        self.allowlisted_sources.add(source)

        # Remove it from blocked sources if necessary.
        self.blocked_sources.discard(source)

        # Remove temporary rules.
        self.temporary_rules.pop(source, None)

        self._log_event(
            "ALLOWLIST_ADDED",
            source,
        )

    def remove_from_allowlist(self, source: str) -> None:
        """
        Remove a source from the allowlist.
        """

        self.allowlisted_sources.discard(source)

        self._log_event(
            "ALLOWLIST_REMOVED",
            source,
        )

    def is_allowlisted(self, source: str) -> bool:
        """
        Check whether a source is allowlisted.
        """

        return source in self.allowlisted_sources

    # ========================================================
    # PERMANENT BLOCKING
    # ========================================================

    def block(
        self,
        source: str,
        reason: str = "",
    ) -> None:
        """
        Permanently block a source.
        """

        # An allowlisted source cannot be blocked.
        if self.is_allowlisted(source):
            self._log_event(
                "BLOCK_IGNORED_ALLOWLISTED",
                source,
                {
                    "reason": reason,
                },
            )

            return

        self.blocked_sources.add(source)

        # Remove temporary rule if permanent block is added.
        self.temporary_rules.pop(source, None)

        self._log_event(
            "BLOCKED",
            source,
            {
                "reason": reason,
            },
        )

    def unblock(self, source: str) -> None:
        """
        Remove a permanent block.
        """

        self.blocked_sources.discard(source)

        self._log_event(
            "UNBLOCKED",
            source,
        )

    def is_blocked(self, source: str) -> bool:
        """
        Check whether a source is permanently blocked.
        """

        return source in self.blocked_sources

    # ========================================================
    # TEMPORARY BLOCKING
    # ========================================================

    def temporary_block(
        self,
        source: str,
        duration: float,
        reason: str = "",
    ) -> None:
        """
        Temporarily block a source.

        Parameters
        ----------
        source : str
            Source to block.

        duration : float
            Duration in seconds.
        """

        if not isinstance(duration, (int, float)):
            raise TypeError(
                "duration must be numeric"
            )

        duration = float(duration)

        if duration <= 0:
            raise ValueError(
                "duration must be greater than 0"
            )

        # Allowlisted sources cannot be temporarily blocked.
        if self.is_allowlisted(source):
            self._log_event(
                "TEMPORARY_BLOCK_IGNORED_ALLOWLISTED",
                source,
                {
                    "reason": reason,
                },
            )

            return

        now = time.time()

        rule = TemporaryRule(
            source=source,
            created_at=now,
            expires_at=now + duration,
            reason=reason,
        )

        self.temporary_rules[source] = rule

        self._log_event(
            "TEMPORARY_BLOCKED",
            source,
            {
                "duration": duration,
                "reason": reason,
            },
        )

    def remove_temporary_rule(self, source: str) -> None:
        """
        Remove a temporary firewall rule.
        """

        if source in self.temporary_rules:

            del self.temporary_rules[source]

            self._log_event(
                "TEMPORARY_RULE_REMOVED",
                source,
            )

    def has_active_temporary_rule(self, source: str) -> bool:
        """
        Check whether a source currently has an active
        temporary rule.
        """

        self.cleanup_expired_rules()

        return source in self.temporary_rules

    def cleanup_expired_rules(self) -> None:
        """
        Remove expired temporary firewall rules.
        """

        now = time.time()

        expired_sources = []

        for source, rule in self.temporary_rules.items():

            if now >= rule.expires_at:
                expired_sources.append(source)

        for source in expired_sources:

            del self.temporary_rules[source]

            self._log_event(
                "TEMPORARY_RULE_EXPIRED",
                source,
            )

    # ========================================================
    # FIREWALL DECISION
    # ========================================================

    def check(
        self,
        source: str,
    ) -> bool:
        """
        Check whether a source is allowed.

        Returns
        -------
        bool
            True if allowed.
            False if blocked.
        """

        self.cleanup_expired_rules()

        self.total_requests += 1

        # Allowlist has highest priority.
        if self.is_allowlisted(source):

            self.allowed_requests += 1

            self._log_event(
                "REQUEST_ALLOWED_ALLOWLIST",
                source,
            )

            return True

        # Permanent block.
        if self.is_blocked(source):

            self.blocked_requests += 1

            self._log_event(
                "REQUEST_BLOCKED",
                source,
                {
                    "rule": "PERMANENT",
                },
            )

            return False

        # Temporary block.
        if self.has_active_temporary_rule(source):

            self.blocked_requests += 1

            self._log_event(
                "REQUEST_BLOCKED",
                source,
                {
                    "rule": "TEMPORARY",
                },
            )

            return False

        # Default allow.
        self.allowed_requests += 1

        self._log_event(
            "REQUEST_ALLOWED",
            source,
        )

        return True

    # ========================================================
    # ADAPTIVE EVALUATION
    # ========================================================

    def evaluate(
        self,
        source: str,
        threat_level: float,
    ) -> str:
        """
        Evaluate a source based on its threat level.

        Returns the threat classification.
        """

        classification = self.classify_threat(
            threat_level
        )

        # Critical threat -> permanent block.
        if classification == "CRITICAL":

            self.block(
                source,
                reason="Critical threat detected",
            )

        # High threat -> temporary block.
        elif classification == "HIGH":

            self.temporary_block(
                source,
                duration=300,
                reason="High threat detected",
            )

        self._log_event(
            "THREAT_EVALUATED",
            source,
            {
                "threat_level": threat_level,
                "classification": classification,
            },
        )

        return classification

    # ========================================================
    # EVENTS
    # ========================================================

    def get_events(self) -> List[dict]:
        """
        Return a copy of firewall events.
        """

        return list(self.events)

    # ========================================================
    # SUMMARY
    # ========================================================

    def summary(self) -> dict:
        """
        Return firewall statistics.
        """

        self.cleanup_expired_rules()

        return {
            "allowlisted_sources": len(
                self.allowlisted_sources
            ),

            "blocked_sources": len(
                self.blocked_sources
            ),

            "active_temporary_rules": len(
                self.temporary_rules
            ),

            "total_requests": self.total_requests,

            "allowed_requests": self.allowed_requests,

            "blocked_requests": self.blocked_requests,

            "events": len(
                self.events
            ),
        }


# ============================================================
# OPTIONAL QUICK TEST
# ============================================================

if __name__ == "__main__":

    firewall = AdaptiveFirewall()

    print(
        "0.05 ->",
        firewall.classify_threat(0.05),
    )

    print(
        "0.10 ->",
        firewall.classify_threat(0.10),
    )

    print(
        "0.30 ->",
        firewall.classify_threat(0.30),
    )

    print(
        "0.60 ->",
        firewall.classify_threat(0.60),
    )

    print(
        "0.80 ->",
        firewall.classify_threat(0.80),
    )

    print(
        "0.95 ->",
        firewall.classify_threat(0.95),
    )

    print()
    print(firewall.summary())