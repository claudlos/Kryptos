"""Helpers for exporting dashboard data consumed by the static site."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .catalog import BENCHMARKS, PROJECT_METADATA, anchor_catalog, clue_catalog, list_strategy_specs
from .models import StrategyResult
from .paths import ensure_parent


def build_dashboard_payload(
    run_summary: dict[str, Any] | None = None,
    *,
    research_memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": PROJECT_METADATA,
        "benchmarks": BENCHMARKS,
        "anchors": anchor_catalog(),
        "clues": clue_catalog(),
        "strategy_catalog": list_strategy_specs(),
        "latest_run": run_summary,
        "research_memory": research_memory,
    }


def serialize_run_summary(results: list[StrategyResult], strategy_selection: str) -> dict[str, Any]:
    total_attempts = sum(result.metrics.attempts for result in results)
    total_unique = sum(result.metrics.unique_attempts or 0 for result in results)
    total_elapsed = sum(result.metrics.elapsed_seconds or 0.0 for result in results)
    return {
        "strategy_selection": strategy_selection,
        "result_count": len(results),
        "totals": {
            "attempts": total_attempts,
            "unique_attempts": total_unique,
            "elapsed_seconds": round(total_elapsed, 6),
        },
        "results": [result.to_dict() for result in results],
    }


def write_json(path: str | Path, payload: dict[str, Any]) -> Path:
    destination = ensure_parent(path)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination
