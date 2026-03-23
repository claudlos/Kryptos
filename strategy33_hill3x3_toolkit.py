from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import build_ranked_candidate, dedupe_ranked_candidates
from kryptos.models import SearchMetrics, StrategyResult
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.standalone_bridge import preview_from_text, run_script_and_load_json

SPEC = get_strategy_spec("33")
SCRIPT_NAME = "strategy33_hill3x3.py"
OUTPUT_PATH = "runs/hill_3x3.json"


def run(config: StrategyRuntimeConfig | None = None) -> StrategyResult:
    config = config or StrategyRuntimeConfig()
    payload = run_script_and_load_json(SCRIPT_NAME, OUTPUT_PATH)
    top_results = list(payload.get("top_results", []))
    candidates = []
    for result in top_results[: max(config.candidate_limit * 4, 12)]:
        plaintext = str(result.get("text", ""))
        if not plaintext:
            continue
        candidates.append(
            build_ranked_candidate(
                plaintext,
                transform_chain=[f"hill3x3:{result.get('keyword', 'unknown')}:width={result.get('width', '?')}"],
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material={
                    "width": result.get("width"),
                    "keyword": result.get("keyword"),
                    "permutation": result.get("permutation"),
                    "phase": result.get("phase"),
                    "key_matrix": result.get("key_matrix"),
                },
                structure_hint=220,
            )
        )
    ranked = dedupe_ranked_candidates(candidates)
    status = "candidate" if ranked else "no_match"
    summary = (
        f"Standalone Hill 3x3 sweep retained {len(top_results)} candidate records; top structured score {ranked[0]['total_score']}/1000."
        if ranked
        else "Standalone Hill 3x3 sweep found no retained candidates."
    )
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status=status,
        summary=summary,
        best_preview=preview_from_text(ranked[0]["plaintext"]) if ranked else "No Hill 3x3 candidate retained.",
        matched_clues=list(ranked[0]["matched_clues"]) if ranked else [],
        metrics=SearchMetrics(
            attempts=int(payload.get("total_candidates", 0)),
            unique_attempts=int(payload.get("total_candidates", 0)),
        ),
        notes=[
            "Runs the existing standalone Hill 3x3 script and hydrates its JSON artifact into the toolkit result schema.",
            payload.get("_stdout_tail", ""),
        ],
        artifacts={
            "top_candidates": ranked[: max(config.candidate_limit, 8)],
            "raw_report": payload,
        },
    )
