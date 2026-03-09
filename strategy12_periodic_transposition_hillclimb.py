from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import build_ranked_candidate, build_score_breakdown, build_strategy_result, sort_ranked_candidates
from kryptos.constants import DEFAULT_KEYWORDS, K4
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import hillclimb_permutation, identity_permutation, keyword_permutation

SPEC = get_strategy_spec("12")


def resolve_periodic_search_space(config: StrategyRuntimeConfig, ciphertext: str = K4) -> tuple[tuple[int, ...], tuple[str, ...]]:
    widths = [width for width in range(config.width_min, min(config.width_max, len(ciphertext) - 1) + 1)]
    return config.ordered_widths(widths), config.ordered_keywords(DEFAULT_KEYWORDS)


def search_periodic_candidates(ciphertext: str = K4, config: StrategyRuntimeConfig | None = None) -> tuple[list[dict[str, object]], int]:
    config = config or StrategyRuntimeConfig()
    widths, keywords = resolve_periodic_search_space(config, ciphertext)
    attempts = 0
    candidates: list[dict[str, object]] = []

    def scorer(candidate_text: str):
        breakdown = build_score_breakdown(
            candidate_text,
            corpus_bundle=config.corpora,
            scorer_profile=config.scorer_profile,
            structure_hint=180,
        )
        return breakdown["total"], breakdown

    for width in widths:
        seed_permutations = [identity_permutation(width), *[keyword_permutation(keyword, width) for keyword in keywords]]
        for seed_keyword, permutation in zip(["IDENTITY", *keywords], seed_permutations):
            for fill_mode, read_mode in (("row", "column"), ("column", "row")):
                for reverse_rows in (False, True):
                    for reverse_columns in (False, True):
                        attempts += 1
                        result = hillclimb_permutation(
                            ciphertext,
                            width,
                            permutation,
                            scorer,
                            fill_mode=fill_mode,
                            read_mode=read_mode,
                            reverse_rows=reverse_rows,
                            reverse_columns=reverse_columns,
                        )
                        candidates.append(
                            build_ranked_candidate(
                                str(result["plaintext"]),
                                transform_chain=[f"periodic_transposition:w{width}:{fill_mode}->{read_mode}"],
                                corpus_bundle=config.corpora,
                                scorer_profile=config.scorer_profile,
                                key_material={
                                    "keyword_seed": seed_keyword,
                                    "width": width,
                                    "permutation": list(result["permutation"]),
                                    "fill_mode": fill_mode,
                                    "read_mode": read_mode,
                                    "reverse_rows": reverse_rows,
                                    "reverse_columns": reverse_columns,
                                },
                                structure_hint=180,
                            )
                        )
    return sort_ranked_candidates(candidates), attempts


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    widths, keywords = resolve_periodic_search_space(config)
    candidates, attempts = search_periodic_candidates(config=config)
    retained = candidates[: max(config.candidate_limit, 8)]
    notes = [
        f"Searched widths {min(widths)}-{max(widths)} with row/column orientations, reversals, and {len(keywords)} keyword-seeded permutations.",
        "Used local swap hillclimbs instead of raw Cartesian brute force over every permutation.",
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
