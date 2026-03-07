"""Structured result models used by the CLI and dashboard exporter."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class SearchMetrics:
    attempts: int = 0
    unique_attempts: int | None = None
    repeated_attempts: int | None = None
    elapsed_seconds: float | None = None


@dataclass(slots=True)
class StrategyResult:
    strategy_id: str
    name: str
    objective: str
    hypothesis: str
    status: str
    summary: str
    best_preview: str = ""
    matched_clues: list[str] = field(default_factory=list)
    metrics: SearchMetrics = field(default_factory=SearchMetrics)
    notes: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

