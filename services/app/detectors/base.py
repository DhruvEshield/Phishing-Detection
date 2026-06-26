"""Base Signal dataclass — the unit every detector returns."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Signal:
    """
    One detector's output. ScoringEngine aggregates N Signals into a total score.

    raw_score  : 0–100 float from this detector alone.
    weight     : configured weight for this signal type (0–1).
    flags      : human-readable strings explaining what fired (explainability).
    metadata   : arbitrary structured data for the explanation payload.
    """
    name: str
    raw_score: float        # 0–100
    weight: float           # 0–1 (set by ScoringConfig)
    flags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def weighted_contribution(self) -> float:
        return round(self.raw_score * self.weight, 4)

    def to_breakdown(self) -> dict:
        return {
            "signal_name": self.name,
            "raw_score": round(self.raw_score, 2),
            "weight": self.weight,
            "weighted_contribution": self.weighted_contribution,
            "flags": self.flags,
            "metadata": self.metadata,
        }
