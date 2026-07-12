"""Scoring configuration — loads thresholds and weights; validates the invariant.

INVARIANT: no single signal can independently breach the high-risk threshold.
  max(weight_i) * 100 < high_threshold  for all i
  Checked at startup (main.py lifespan) and in tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.config import Settings


@dataclass
class ScoringConfig:
    high_threshold: float
    medium_threshold: float
    weights: dict[str, float]  # signal_name → weight

    def validate_invariant(self) -> None:
        """
        Enforce the single-signal block invariant.
        Raises ValueError on misconfiguration so the app fails fast at startup.
        """
        for name, w in self.weights.items():
            max_single = w * 100.0
            if max_single >= self.high_threshold:
                raise ValueError(
                    f"Scoring invariant VIOLATED: signal '{name}' weight={w} "
                    f"× 100 = {max_single} ≥ high_threshold={self.high_threshold}. "
                    f"Reduce weight or raise high_threshold so no single signal "
                    f"can independently trigger a block."
                )

    @classmethod
    def from_settings(cls, settings: "Settings") -> "ScoringConfig":
        return cls(
            high_threshold=settings.high_threshold,
            medium_threshold=settings.medium_threshold,
            weights={
                "header":       settings.weight_header,
                "content":      settings.weight_content,
                "url":          settings.weight_url,
                "qrcode":       settings.weight_qrcode,
                "threat_intel": settings.weight_threat_intel,
                "attachment":   settings.weight_attachment,
            },
        )
