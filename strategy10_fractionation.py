from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    analyze_layered_candidate,
    build_ranked_candidate,
    build_strategy_result,
    dedupe_ranked_candidates,
    decrypt_bifid,
    generate_polybius_square,
)
from kryptos.constants import DEFAULT_KEYWORDS, DEFAULT_PERIODS, K4
from kryptos.runtime import StrategyRuntimeConfig

SPEC = get_strategy_spec("10")


def generate_fractionation_candidates(ciphertext: str = K4, config: StrategyRuntimeConfig | None = None) -> tuple[list[dict[str, object]], int]:
    config = config or StrategyRuntimeConfig()
    cache_key = config.stage_cache_key("fractionation", ciphertext)
    cached = config.get_stage_cache(cache_key)
    if cached is not None:
        return list(cached), 0
    direct_candidates: list[dict[str, object]] = []
    attempts = 0
    for keyword in DEFAULT_KEYWORDS:
        square = generate_polybius_square(keyword)
        for period in DEFAULT_PERIODS:
            attempts += 1
            bifid_plaintext = decrypt_bifid(period, ciphertext, square)
            direct_candidates.append(
                build_ranked_candidate(
                    bifid_plaintext,
                    transform_chain=[f"bifid:{keyword}:period={period}"],
                    corpus_bundle=config.corpora,
                    scorer_profile=config.scorer_profile,
                    key_material={"keyword": keyword, "period": period},
                    structure_hint=80,
                )
            )

    ranked_direct = dedupe_ranked_candidates(direct_candidates)
    shortlist = ranked_direct[: max(config.candidate_limit * 4, 12)]
    expanded = list(shortlist)
    for candidate in shortlist:
        layered = analyze_layered_candidate(
            str(candidate["plaintext"]),
            max_key_length=config.max_post_key_length,
            corpus_bundle=config.corpora,
            scorer_profile=config.scorer_profile,
        )
        expanded.append(
            build_ranked_candidate(
                str(layered["plaintext"]),
                transform_chain=[*candidate["transform_chain"], *layered["transform_chain"]],
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material={**dict(candidate["key_material"]), **dict(layered["key_material"])},
                structure_hint=160,
            )
        )
    ranked = dedupe_ranked_candidates(expanded)
    config.set_stage_cache(cache_key, tuple(ranked))
    return ranked, attempts


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    candidates, attempts = generate_fractionation_candidates(config=config)
    retained = candidates[: max(config.candidate_limit, 8)]
    result = build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=[
            f"Evaluated {len(DEFAULT_KEYWORDS)} keywords across {len(DEFAULT_PERIODS)} periods.",
            "Expanded only the best direct Bifid candidates through repeating-key, autokey, and periodic-transposition post layers.",
        ],
    )
    result.artifacts["candidate_count"] = len(candidates)
    return result
