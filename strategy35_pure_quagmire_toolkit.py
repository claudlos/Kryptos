from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import build_ranked_candidate, dedupe_ranked_candidates
from kryptos.models import SearchMetrics, StrategyResult
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.standalone_bridge import preview_from_text, run_script_and_load_json

SPEC = get_strategy_spec("35")
SCRIPT_NAME = "strategy35_pure_quagmire.py"
OUTPUT_PATH = "runs/pure_quagmire.json"


def run(config: StrategyRuntimeConfig | None = None) -> StrategyResult:
    config = config or StrategyRuntimeConfig()
    payload = run_script_and_load_json(SCRIPT_NAME, OUTPUT_PATH)
    candidate_records = []
    if payload.get("best_result"):
        candidate_records.append(payload["best_result"])
    candidate_records.extend(payload.get("top_20", []))
    candidate_records.extend(payload.get("top_anchor_matches", []))

    candidates = []
    seen = set()
    for record in candidate_records:
        plaintext = str(record.get("plaintext", ""))
        if not plaintext or plaintext in seen:
            continue
        seen.add(plaintext)
        candidates.append(
            build_ranked_candidate(
                plaintext,
                transform_chain=[
                    f"pure_quagmire:{record.get('keyword', 'unknown')}:key_offset={record.get('key_offset', '?')}:pos_offset={record.get('pos_offset', '?')}"
                ],
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material={
                    "keyword": record.get("keyword"),
                    "key_offset": record.get("key_offset"),
                    "pos_offset": record.get("pos_offset"),
                },
                structure_hint=180,
            )
        )
    ranked = dedupe_ranked_candidates(candidates)
    status = "candidate" if ranked else "no_match"
    summary = (
        f"Pure Quagmire deep search tested {payload.get('total_configurations', 0)} configurations; best structured score {ranked[0]['total_score']}/1000."
        if ranked
        else f"Pure Quagmire deep search tested {payload.get('total_configurations', 0)} configurations with no retained candidate."
    )
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status=status,
        summary=summary,
        best_preview=preview_from_text(ranked[0]["plaintext"]) if ranked else "No pure Quagmire candidate retained.",
        matched_clues=list(ranked[0]["matched_clues"]) if ranked else [],
        metrics=SearchMetrics(
            attempts=int(payload.get("total_configurations", 0)),
            unique_attempts=int(payload.get("total_configurations", 0)),
        ),
        notes=[
            "Runs the existing standalone pure Quagmire script and hydrates the JSON artifact into the toolkit result schema.",
            payload.get("_stdout_tail", ""),
        ],
        artifacts={
            "top_candidates": ranked[: max(config.candidate_limit, 8)],
            "raw_report": payload,
        },
    )
