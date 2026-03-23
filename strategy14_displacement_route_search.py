from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import build_displacement_route_candidates, build_strategy_result, dedupe_ranked_candidates, transform_family
from kryptos.runtime import StrategyRuntimeConfig
from strategy10_fractionation import generate_fractionation_candidates
from strategy12_periodic_transposition_hillclimb import search_periodic_candidates

SPEC = get_strategy_spec("14")


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    fractionation_stage, fractionation_attempts = generate_fractionation_candidates(config=config)
    periodic_stage, periodic_attempts = search_periodic_candidates(config=config)

    source_limit = max(config.candidate_limit, config.route_followup_limit * 2, 6)
    source_candidates = dedupe_ranked_candidates(
        fractionation_stage[:source_limit] + periodic_stage[:source_limit]
    )[: source_limit * 2]

    candidates: list[dict[str, object]] = []
    displacement_attempts = 0
    for source_candidate in source_candidates:
        candidates.extend(
            build_displacement_route_candidates(
                str(source_candidate["plaintext"]),
                transform_chain=list(source_candidate["transform_chain"]),
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material={
                    "source_family": list(transform_family(list(source_candidate["transform_chain"]))),
                    "source_key_material": dict(source_candidate["key_material"]),
                },
                corpus_id=source_candidate.get("corpus_id"),
                displacement_window=config.displacement_window,
                route_followup_limit=config.route_followup_limit,
            )
        )
        displacement_attempts += config.displacement_window * 2

    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[: max(config.candidate_limit, 8)]
    result = build_strategy_result(
        SPEC,
        retained,
        attempts=fractionation_attempts + periodic_attempts + displacement_attempts,
        notes=[
            "Started from the strongest fractionation and periodic-transposition candidates, then realigned clue-bearing segments with bounded displacement offsets.",
            "Each follow-up candidate is reranked with both anchor-first and geo-route scoring to reward stronger Berlin/world-clock route structure.",
        ],
    )
    result.artifacts["candidate_count"] = len(ranked)
    result.artifacts["source_candidate_count"] = len(source_candidates)
    return result
