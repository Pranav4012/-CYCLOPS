"""
Adaptive Firewall Module

This module provides a lightweight adaptive firewall policy engine.

Features:
- Allowlist management
- Blocklist management
- Threat-level based decisions
- Temporary blocking rules
- Rule expiration
- Request evaluation
- Firewall event logging
- Firewall summary
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Any


# ============================================================
# FIREWALL DECISION
# ============================================================

@dataclass
class FirewallDecision:
    """
    Represents the result of a firewall evaluation.
    """

    allowed: bool
    action: str
    reason: str
    source: str
    threat_level: Optional[float] = None
    classification: Optional[str] = None

    def __getitem__(self, key: str):
        """Allow dictionary-style access for compatibility."""

        return self.to_dict()[key]

    def to_dict(self) -> dict:
        """
        Convert the decision into a dictionary.
        """

        return {
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "source": self.source,
            "threat_level": self.threat_level,
            "classification": self.classification,
        }


# ============================================================
# TEMPORARY RULE
# ============================================================

@dataclass
class TemporaryRule:
    """
    Represents a temporary firewall rule.
    """

    source: str
    action: str
    reason: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    threat_level: Optional[float] = None

    def is_expired(self) -> bool:
        """
        Return True if the rule has expired.
        """

        if self.expires_at is None:
            return False

        return datetime.utcnow() >= self.expires_at

    def to_dict(self) -> dict:
        """
        Convert the rule into a dictionary.
        """

        return {
            "source": self.source,
            "action": self.action,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "expires_at": (
                self.expires_at.isoformat()
                if self.expires_at is not None
                else None
            ),
            "threat_level": self.threat_level,
            "expired": self.is_expired(),
        }


# ============================================================
# ADAPTIVE FIREWALL
# ============================================================

class AdaptiveFirewall:
    """
    Adaptive firewall policy engine.

    The firewall evaluates a source using:

    1. Allowlist
    2. Permanent blocklist
    3. Temporary rules
    4. Threat level

    Higher threat levels can automatically result in blocking.
    """

    # Threat thresholds
    LOW_THREAT = 0.10
    MEDIUM_THREAT = 0.30
    HIGH_THREAT = 0.60
    CRITICAL_THREAT = 0.90

    def __init__(self) -> None:
        """
        Initialize an empty firewall.
        """

        # Trusted sources
        self.allowlist: set[str] = set()

        # Permanently blocked sources
        self.blocklist: set[str] = set()

        # Temporary rules
        self.temporary_rules: dict[str, TemporaryRule] = {}

        # Firewall event history
        self.events: list[dict[str, Any]] = []

        # Statistics
        self.total_requests = 0
        self.allowed_requests = 0
        self.blocked_requests = 0

    # ========================================================
    # ALLOWLIST
    # ========================================================

    def add_to_allowlist(self, source: str) -> bool:
        """
        Add a source to the allowlist.

        A source cannot remain permanently blocked and allowed
        at the same time, so it is removed from the blocklist.
        """

        source = self._normalize_source(source)

        if source in self.allowlist:
            self._log_event(
                source=source,
                action="ALLOWLIST_ADD",
                reason="Source already on allowlist",
            )
            return False

        self.allowlist.add(source)
        self.blocklist.discard(source)
        self.temporary_rules.pop(source, None)

        self._log_event(
            source=source,
            action="ALLOWLIST_ADD",
            reason="Source added to allowlist",
        )

        return True

    def remove_from_allowlist(self, source: str) -> bool:
        """
        Remove a source from the allowlist.

        Returns True if the source existed.
        """

        source = self._normalize_source(source)

        if source not in self.allowlist:
            return False

        self.allowlist.remove(source)

        self._log_event(
            source=source,
            action="ALLOWLIST_REMOVE",
            reason="Source removed from allowlist",
        )

        return True

    def is_allowlisted(self, source: str) -> bool:
        """
        Check whether a source is allowlisted.
        """

        source = self._normalize_source(source)

        return source in self.allowlist

    # ========================================================
    # BLOCKLIST
    # ========================================================

    def block(
        self,
        source: str,
        reason: str = "Blocked by firewall",
        threat_level: Optional[float] = None,
    ) -> bool:
        """
        Permanently block a source.
        """

        source = self._normalize_source(source)

        if source in self.blocklist:
            self._log_event(
                source=source,
                action="BLOCK",
                reason="Source already permanently blocked",
                threat_level=threat_level,
            )
            return False

        self.allowlist.discard(source)
        self.blocklist.add(source)

        # Remove temporary rule because permanent blocking
        # has higher priority.
        self.temporary_rules.pop(source, None)

        self._log_event(
            source=source,
            action="BLOCK",
            reason=reason,
            threat_level=threat_level,
        )

        return True

    def unblock(self, source: str) -> bool:
        """
        Remove a source from the permanent blocklist.

        Returns True if the source existed.
        """

        source = self._normalize_source(source)

        if source not in self.blocklist:
            return False

        self.blocklist.remove(source)

        self._log_event(
            source=source,
            action="UNBLOCK",
            reason="Source removed from permanent blocklist",
        )

        return True

    def is_blocked(self, source: str) -> bool:
        """
        Check whether a source is permanently or temporarily blocked.
        """

        source = self._normalize_source(source)

        self.cleanup_expired_rules()

        return source in self.blocklist or source in self.temporary_rules

    # ========================================================
    # TEMPORARY BLOCKING
    # ========================================================

    def temporary_block(
        self,
        source: str,
        duration_seconds: int = 60,
        reason: str = "Temporary security block",
        threat_level: Optional[float] = None,
    ) -> bool:
        """
        Temporarily block a source.

        Parameters
        ----------
        source:
            Source identifier.

        duration_seconds:
            Duration of the temporary block.

        reason:
            Explanation for the rule.

        threat_level:
            Optional threat score.
        """

        source = self._normalize_source(source)

        if duration_seconds <= 0:
            raise ValueError(
                "duration_seconds must be greater than zero"
            )

        created_at = datetime.utcnow()

        expires_at = (
            created_at
            + timedelta(seconds=duration_seconds)
        )

        rule = TemporaryRule(
            source=source,
            action="BLOCK",
            reason=reason,
            created_at=created_at,
            expires_at=expires_at,
            threat_level=threat_level,
        )

        self.allowlist.discard(source)
        self.blocklist.discard(source)
        self.temporary_rules[source] = rule

        self._log_event(
            source=source,
            action="TEMPORARY_BLOCK",
            reason=reason,
            threat_level=threat_level,
        )

        return True

    def remove_temporary_rule(self, source: str) -> bool:
        """
        Remove a temporary rule manually.
        """

        source = self._normalize_source(source)

        if source not in self.temporary_rules:
            return False

        del self.temporary_rules[source]

        self._log_event(
            source=source,
            action="TEMPORARY_RULE_REMOVE",
            reason="Temporary firewall rule removed",
        )

        return True

    def cleanup_expired_rules(self) -> int:
        """
        Remove expired temporary rules.

        Returns the number of rules removed.
        """

        expired_sources = []

        for source, rule in self.temporary_rules.items():
            if rule.is_expired():
                expired_sources.append(source)

        for source in expired_sources:
            del self.temporary_rules[source]

            self._log_event(
                source=source,
                action="TEMPORARY_RULE_EXPIRED",
                reason="Temporary firewall rule expired",
            )

        return len(expired_sources)

    def has_active_temporary_rule(
        self,
        source: str,
    ) -> bool:
        """
        Check whether a source has an active temporary rule.
        """

        source = self._normalize_source(source)

        self.cleanup_expired_rules()

        return source in self.temporary_rules

    # ========================================================
    # THREAT LEVEL
    # ========================================================

    def classify_threat(
        self,
        threat_level: Optional[float],
    ) -> str:
        """
        Convert a numeric threat level into a label.

        Expected range: 0.0 to 1.0.
        """

        if threat_level is None:
            return "UNKNOWN"

        threat_level = self._validate_threat_level(
            threat_level
        )

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
    # REQUEST EVALUATION
    # ========================================================

    def evaluate(
        self,
        source: str,
        threat_level: Optional[float] = None,
    ) -> FirewallDecision:
        """
        Evaluate whether a source should be allowed.

        Decision priority:

        1. Allowlist
        2. Permanent blocklist
        3. Temporary block
        4. Threat level
        5. Default allow
        """

        source = self._normalize_source(source)

        self.total_requests += 1

        # Remove expired rules before evaluation.
        self.cleanup_expired_rules()

        # ----------------------------------------------------
        # 1. ALLOWLIST
        # ----------------------------------------------------

        if source in self.allowlist:

            decision = FirewallDecision(
                allowed=True,
                action="ALLOW",
                reason="Source is on allowlist",
                source=source,
                threat_level=threat_level,
                classification=(
                    self.classify_threat(threat_level)
                    if threat_level is not None
                    else None
                ),
            )

            self.allowed_requests += 1

            self._record_decision(decision)

            return decision

        # ----------------------------------------------------
        # 2. PERMANENT BLOCKLIST
        # ----------------------------------------------------

        if source in self.blocklist:

            decision = FirewallDecision(
                allowed=False,
                action="BLOCK",
                reason="Source is permanently blocked",
                source=source,
                threat_level=threat_level,
                classification=(
                    self.classify_threat(threat_level)
                    if threat_level is not None
                    else None
                ),
            )

            self.blocked_requests += 1

            self._record_decision(decision)

            return decision

        # ----------------------------------------------------
        # 3. TEMPORARY RULE
        # ----------------------------------------------------

        if source in self.temporary_rules:

            rule = self.temporary_rules[source]

            decision = FirewallDecision(
                allowed=False,
                action="BLOCK",
                reason=rule.reason,
                source=source,
                threat_level=threat_level,
                classification=(
                    self.classify_threat(threat_level)
                    if threat_level is not None
                    else None
                ),
            )

            self.blocked_requests += 1

            self._record_decision(decision)

            return decision

        # ----------------------------------------------------
        # 4. THREAT LEVEL
        # ----------------------------------------------------

        if threat_level is not None:

            threat_level = self._validate_threat_level(
                threat_level
            )

            classification = self.classify_threat(
                threat_level
            )

            # Critical threats are automatically blocked.
            if threat_level >= self.CRITICAL_THREAT:

                decision = FirewallDecision(
                    allowed=False,
                    action="BLOCK",
                    reason=(
                        "Critical threat level detected"
                    ),
                    source=source,
                    threat_level=threat_level,
                    classification=classification,
                )

                self.blocked_requests += 1

                self._record_decision(decision)

                return decision

            # High threats are temporarily blocked.
            if threat_level >= self.HIGH_THREAT:

                self.temporary_block(
                    source=source,
                    duration_seconds=300,
                    reason=(
                        "High threat level triggered "
                        "automatic temporary block"
                    ),
                    threat_level=threat_level,
                )

                decision = FirewallDecision(
                    allowed=False,
                    action="BLOCK",
                    reason=(
                        "High threat level triggered "
                        "temporary block"
                    ),
                    source=source,
                    threat_level=threat_level,
                    classification=classification,
                )

                self.blocked_requests += 1

                self._record_decision(decision)

                return decision

            # Medium threats are allowed but marked.
            if threat_level >= self.MEDIUM_THREAT:

                decision = FirewallDecision(
                    allowed=True,
                    action="ALLOW_MONITOR",
                    reason=(
                        f"{classification} threat level "
                        "allowed with monitoring"
                    ),
                    source=source,
                    threat_level=threat_level,
                    classification=classification,
                )

                self.allowed_requests += 1

                self._record_decision(decision)

                return decision

        # ----------------------------------------------------
        # 5. DEFAULT ALLOW
        # ----------------------------------------------------

        decision = FirewallDecision(
            allowed=True,
            action="ALLOW",
            reason="No firewall rule blocked the source",
            source=source,
            threat_level=threat_level,
            classification=(
                self.classify_threat(threat_level)
                if threat_level is not None
                else None
            ),
        )

        self.allowed_requests += 1

        self._record_decision(decision)

        return decision

    # ========================================================
    # CONVENIENCE METHODS
    # ========================================================

    def allow(
        self,
        source: str,
        threat_level: Optional[float] = None,
    ) -> FirewallDecision:
        """
        Alias for evaluate().
        """

        return self.evaluate(
            source=source,
            threat_level=threat_level,
        )

    def check(
        self,
        source: str,
        threat_level: Optional[float] = None,
    ) -> FirewallDecision:
        """
        Check a source against the firewall.
        """

        return self.evaluate(
            source=source,
            threat_level=threat_level,
        )

    # ========================================================
    # EVENT LOGGING
    # ========================================================

    def _log_event(
        self,
        source: str,
        action: str,
        reason: str,
        threat_level: Optional[float] = None,
    ) -> None:
        """
        Store an internal firewall event.
        """

        self.events.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "source": source,
                "action": action,
                "reason": reason,
                "threat_level": threat_level,
            }
        )

    def _record_decision(
        self,
        decision: FirewallDecision,
    ) -> None:
        """
        Record a firewall decision.
        """

        self._log_event(
            source=decision.source,
            action=decision.action,
            reason=decision.reason,
            threat_level=decision.threat_level,
        )

    def get_events(
        self,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Return firewall events.
        """

        if limit is None:
            return list(self.events)

        if limit <= 0:
            return []

        return list(self.events[-limit:])

    # ========================================================
    # SUMMARY
    # ========================================================

    def summary(self) -> dict[str, Any]:
        """
        Return a summary of the firewall state.
        """

        self.cleanup_expired_rules()

        return {
            "allowlisted_sources": len(
                self.allowlist
            ),
            "blocked_sources": len(
                self.blocklist
            ),
            "active_temporary_rules": len(
                self.temporary_rules
            ),
            "total_requests": self.total_requests,
            "allowed_requests": self.allowed_requests,
            "blocked_requests": self.blocked_requests,
            "events": len(self.events),
        }

    # ========================================================
    # VALIDATION
    # ========================================================

    @staticmethod
    def _normalize_source(source: str) -> str:
        """
        Validate and normalize a source identifier.
        """

        if not isinstance(source, str):
            raise TypeError(
                "source must be a string"
            )

        source = source.strip()

        if not source:
            raise ValueError(
                "source cannot be empty"
            )

        return source

    @staticmethod
    def _validate_threat_level(
        threat_level: float,
    ) -> float:
        """
        Validate a threat level.

        Valid range is 0.0 to 1.0.
        """

        if not isinstance(
            threat_level,
            (int, float),
        ):
            raise TypeError(
                "threat_level must be numeric"
            )

        threat_level = float(threat_level)

        if threat_level < 0.0 or threat_level > 1.0:
            raise ValueError(
                "threat_level must be between "
                "0.0 and 1.0"
            )

        return threat_level