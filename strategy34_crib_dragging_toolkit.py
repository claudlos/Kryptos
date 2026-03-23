from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.models import SearchMetrics, StrategyResult
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.standalone_bridge import run_script_and_load_json

SPEC = get_strategy_spec("34")
SCRIPT_NAME = "strategy34_crib_dragging.py"
OUTPUT_PATH = "runs/crib_dragging.json"


def run(config: StrategyRuntimeConfig | None = None) -> StrategyResult:
    _config = config or StrategyRuntimeConfig()
    payload = run_script_and_load_json(SCRIPT_NAME, OUTPUT_PATH)
    methods = payload.get("methods", {})
    vig_top = methods.get("vigenere_shift_autocorrelation", {}).get("top_lags", [])[:5]
    beau_top = methods.get("beaufort_shift_autocorrelation", {}).get("top_lags", [])[:5]
    summary = (
        f"Crib-dragging analysis completed. Top Vigenere lags: {vig_top or 'none'}; "
        f"top Beaufort lags: {beau_top or 'none'}."
    )
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status="analysis",
        summary=summary,
        best_preview=summary,
        matched_clues=[],
        metrics=SearchMetrics(attempts=len(payload.get("known_positions", [])), unique_attempts=len(payload.get("known_positions", []))),
        notes=[
            "Runs the standalone crib-dragging analysis script and exposes its JSON artifact through the toolkit.",
            payload.get("_stdout_tail", ""),
        ],
        artifacts={
            "raw_report": payload,
            "top_vigenere_lags": vig_top,
            "top_beaufort_lags": beau_top,
            "top_candidates": [],
        },
    )
