from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.models import SearchMetrics, StrategyResult
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.standalone_bridge import run_script_and_load_json

SPEC = get_strategy_spec("36")
SCRIPT_NAME = "strategy36_anchor_sensitivity.py"
OUTPUT_PATH = "runs/anchor_sensitivity.json"


def run(config: StrategyRuntimeConfig | None = None) -> StrategyResult:
    _config = config or StrategyRuntimeConfig()
    payload = run_script_and_load_json(SCRIPT_NAME, OUTPUT_PATH)
    summary_info = payload.get("sensitivity_summary", {})
    summary = (
        f"Anchor sensitivity analysis found {summary_info.get('n_shifted_configs_better_than_original', 0)} shifted configs better than the original anchors. "
        f"Best shift: {summary_info.get('best_shifted_label')}; best shifted score: {summary_info.get('best_shifted_score')}."
    )
    attempts = 0
    for entry in payload.get("phase1_consistency", {}).values():
        attempts += int(entry.get("original_stats", {}).get("total_constrained", 0))
        for top in entry.get("top5", []):
            attempts += int(top.get("total_constrained", 0))
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status="analysis",
        summary=summary,
        best_preview=summary,
        matched_clues=[],
        metrics=SearchMetrics(attempts=attempts, unique_attempts=attempts),
        notes=[
            "Runs the standalone anchor sensitivity analysis script and exposes its JSON artifact through the toolkit.",
            payload.get("_stdout_tail", ""),
        ],
        artifacts={
            "raw_report": payload,
            "sensitivity_summary": summary_info,
            "top_candidates": [],
        },
    )
