"""
scoring_engine.py
Implements the risk scoring model from the SRS specification.

Score formula:  S_new = S_previous * (0.98 ^ hours_inactive) + W(event)
Time decay:     S(t) = S_previous * (0.98 ^ delta_t_hours)
"""

import math
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ScoringEngine:
    """
    Calculates and manages attacker risk scores.

    The scoring model is additive: each event adds its weight to the cumulative
    score. Time decay reduces the score exponentially during inactivity periods.
    """

    def __init__(self, config: dict):
        self.event_weights = config["scoring"]["event_weights"]
        self.decay_factor = config["scoring"]["decay_factor"]       # 0.98
        self.thresholds = config["thresholds"]

    def get_event_weight(self, event_type: str, severity: float) -> float:
        """
        Return the configured weight for an event type.
        Falls back to the raw severity value if the event type is unknown.
        """
        # Normalize event type to lowercase with underscores
        normalized = event_type.lower().replace(" ", "_").replace("-", "_")
        weight = self.event_weights.get(normalized, severity)
        logger.debug(f"Event type '{event_type}' normalized to '{normalized}', weight={weight}")
        return float(weight)

    def apply_time_decay(self, current_score: float, last_seen_iso: str) -> float:
        """
        Apply exponential time decay to score based on hours of inactivity.

        Formula: S(t) = S_previous * (0.98 ^ delta_t_hours)
        """
        if current_score <= 0:
            return 0.0

        try:
            # Parse last_seen timestamp (stored as ISO format UTC)
            last_seen = datetime.fromisoformat(last_seen_iso)
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            delta_hours = (now - last_seen).total_seconds() / 3600.0

            if delta_hours <= 0:
                return current_score

            # Apply decay: S * (0.98 ^ hours)
            decayed_score = current_score * math.pow(self.decay_factor, delta_hours)
            decayed_score = max(0.0, decayed_score)  # Score cannot go below zero

            if delta_hours >= 1.0:
                logger.info(
                    f"Time decay applied: score {current_score:.2f} -> {decayed_score:.2f} "
                    f"after {delta_hours:.2f} hours of inactivity"
                )
            return round(decayed_score, 4)

        except (ValueError, TypeError) as e:
            logger.warning(f"Could not apply time decay (bad timestamp): {e}")
            return current_score

    def calculate_new_score(self, current_score: float, last_seen_iso: str,
                             event_type: str, severity: float) -> float:
        """
        Calculate the new risk score after receiving a new event.

        Steps:
        1. Apply time decay to the current score (accounts for inactivity)
        2. Add the event weight to the decayed score
        """
        # Step 1: Decay the existing score
        decayed_score = self.apply_time_decay(current_score, last_seen_iso)

        # Step 2: Add event weight
        event_weight = self.get_event_weight(event_type, severity)
        new_score = decayed_score + event_weight

        logger.info(
            f"Score update: {current_score:.2f} -> decayed={decayed_score:.2f} "
            f"+ event_weight({event_type})={event_weight} -> {new_score:.2f}"
        )
        return round(new_score, 4)

    def determine_status(self, score: float) -> str:
        """
        Map a risk score to a human-readable attacker status.
        Thresholds defined in config.json.
        """
        if score >= self.thresholds["forensic_snapshot"]:
            return "critical"
        elif score >= self.thresholds["noise_injection"]:
            return "high_risk"
        elif score >= self.thresholds["redirect"]:
            return "redirected"
        elif score >= self.thresholds["suspicious"]:
            return "suspicious"
        elif score > 0:
            return "monitoring"
        else:
            return "unknown"

    def evaluate_thresholds(self, score: float, previous_score: float,
                             current_flags: dict) -> list:
        """
        Compare score against thresholds to determine which new actions to trigger.

        Returns a list of action names that have newly been crossed.
        current_flags: dict with keys 'redirected', 'noise_active', 'forensic_captured'
        """
        actions_to_trigger = []

        # Forensic snapshot threshold (100+)
        if (score >= self.thresholds["forensic_snapshot"] and
                not current_flags.get("forensic_captured", 0)):
            actions_to_trigger.append("forensic_snapshot")

        # Network noise injection threshold (70+)
        if (score >= self.thresholds["noise_injection"] and
                not current_flags.get("noise_active", 0)):
            actions_to_trigger.append("noise_injection")

        # Traffic redirection threshold (40+)
        if (score >= self.thresholds["redirect"] and
                not current_flags.get("redirected", 0)):
            actions_to_trigger.append("redirect_to_decoy")

        # Mark suspicious threshold (20+)
        if (score >= self.thresholds["suspicious"] and
                previous_score < self.thresholds["suspicious"]):
            actions_to_trigger.append("mark_suspicious")

        return actions_to_trigger

    def get_threshold_summary(self) -> dict:
        """Return current threshold configuration for display."""
        return {
            "suspicious_threshold": self.thresholds["suspicious"],
            "redirect_threshold": self.thresholds["redirect"],
            "noise_threshold": self.thresholds["noise_injection"],
            "forensic_threshold": self.thresholds["forensic_snapshot"],
            "decay_factor": self.decay_factor,
            "event_weights": self.event_weights
        }
