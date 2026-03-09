from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import analyze_layered_candidate, build_ranked_candidate, build_strategy_result, generate_polybius_square, sort_ranked_candidates, decrypt_bifid
from kryptos.constants import DEFAULT_KEYWORDS, DEFAULT_PERIODS, K4
from kryptos.runtime import StrategyRuntimeConfig

SPEC = get_strategy_spec("10")


def resolve_fractionation_search_space(config: StrategyRuntimeConfig) -> tuple[tuple[str, ...], tuple[int, ...]]:
    return config.ordered_keywords(DEFAULT_KEYWORDS), config.ordered_periods(DEFAULT_PERIODS)


def resolve_fractionation_shortlist_limit(config: StrategyRuntimeConfig, direct_count: int) -> int:
    return config.budgeted_limit(
        max(config.candidate_limit * 4, 12),
        family="bifid",
        max_extra=max(config.candidate_limit, 4),
        ceiling=direct_count,
    )


def generate_fractionation_candidates(ciphertext: str = K4, config: StrategyRuntimeConfig | None = None) -> tuple[list[dict[str, object]], int]:
    config = config or StrategyRuntimeConfig()
    keywords, periods = resolve_fractionation_search_space(config)
    direct_candidates: list[dict[str, object]] = []
    attempts = 0
    for keyword in keywords:
        square = generate_polybius_square(keyword)
        for period in periods:
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

    ranked_direct = sort_ranked_candidates(direct_candidates)
    shortlist_limit = resolve_fractionation_shortlist_limit(config, len(ranked_direct))
    shortlist = ranked_direct[:shortlist_limit]
    expanded = list(shortlist)
    for candidate in shortlist:
        layered = analyze_layered_candidate(
            str(candidate["plaintext"]),
            config=config,
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
    return sort_ranked_candidates(expanded), attempts


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    keywords, periods = resolve_fractionation_search_space(config)
    candidates, attempts = generate_fractionation_candidates(config=config)
    retained = candidates[: max(config.candidate_limit, 8)]
    shortlist_limit = resolve_fractionation_shortlist_limit(config, len(keywords) * len(periods))
    notes = [
        f"Evaluated {len(keywords)} keywords across {len(periods)} periods and expanded a direct shortlist of {shortlist_limit} candidates.",
        "Expanded only the best direct Bifid candidates through repeating-key, autokey, and periodic-transposition post layers.",
    ]
    if config.adaptive_enabled:
        notes.append(config.adaptive_summary())
    result = build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=notes,
    )
    result.artifacts["candidate_count"] = len(candidates)
    return result
