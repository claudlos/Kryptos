from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import analyze_layered_candidate, build_ranked_candidate, build_strategy_result, dedupe_ranked_candidates
from kryptos.constants import K4
from kryptos.runtime import StrategyRuntimeConfig
from strategy10_fractionation import generate_fractionation_candidates
from strategy11_corpus_running_key import generate_running_key_candidates
from strategy12_periodic_transposition_hillclimb import search_periodic_candidates

SPEC = get_strategy_spec("13")


def generate_direct_key_layer_candidates(ciphertext: str, config: StrategyRuntimeConfig) -> list[dict[str, object]]:
    layered = analyze_layered_candidate(
        ciphertext,
        max_key_length=config.max_post_key_length,
        corpus_bundle=config.corpora,
        scorer_profile=config.scorer_profile,
    )
    if layered["mode"] == "direct":
        return []
    return [
        build_ranked_candidate(
            str(layered["plaintext"]),
            transform_chain=["key-layer", *layered["transform_chain"]],
            corpus_bundle=config.corpora,
            scorer_profile=config.scorer_profile,
            key_material=dict(layered["key_material"]),
            structure_hint=220,
        )
    ]


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    stage_beam = max(8, min(config.beam_width, 4096))
    candidates: list[dict[str, object]] = []

    fractionation_stage, fractionation_attempts = generate_fractionation_candidates(config=config)
    periodic_stage, periodic_attempts = search_periodic_candidates(config=config)
    running_stage, running_attempts = generate_running_key_candidates(config=config)

    stage_one = (
        fractionation_stage[: min(stage_beam, 8)]
        + periodic_stage[: min(stage_beam, 8)]
        + running_stage[: min(stage_beam, 8)]
    )
    stage_one.extend(generate_direct_key_layer_candidates(K4, config))
    stage_one = dedupe_ranked_candidates(stage_one)[: min(stage_beam, 10)]

    for candidate in stage_one:
        plaintext = str(candidate["plaintext"])
        if candidate["transform_chain"][0].startswith("bifid"):
            periodic_followups, _ = search_periodic_candidates(plaintext, config)
            for followup in periodic_followups[:1]:
                candidates.append(
                    build_ranked_candidate(
                        str(followup["plaintext"]),
                        transform_chain=[*candidate["transform_chain"], *followup["transform_chain"]],
                        corpus_bundle=config.corpora,
                        scorer_profile=config.scorer_profile,
                        key_material={"stage1": candidate["key_material"], "stage2": followup["key_material"]},
                        corpus_id=str(followup.get("corpus_id") or "hybrid"),
                        structure_hint=240,
                    )
                )
        layered = analyze_layered_candidate(
            plaintext,
            max_key_length=config.max_post_key_length,
            corpus_bundle=config.corpora,
            scorer_profile=config.scorer_profile,
        )
        if layered["mode"] != "direct":
            candidates.append(
                build_ranked_candidate(
                    str(layered["plaintext"]),
                    transform_chain=[*candidate["transform_chain"], *layered["transform_chain"]],
                    corpus_bundle=config.corpora,
                    scorer_profile=config.scorer_profile,
                    key_material={"stage1": candidate["key_material"], "stage2": dict(layered["key_material"])} if layered["key_material"] else {"stage1": candidate["key_material"]},
                    corpus_id=str(candidate.get("corpus_id") or "hybrid"),
                    structure_hint=240,
                )
            )
    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[: max(config.candidate_limit, 8)]
    result = build_strategy_result(
        SPEC,
        retained,
        attempts=fractionation_attempts + periodic_attempts + running_attempts,
        notes=[
            "Composed exactly two stages from fractionation, running-key, key-layer, and periodic-transposition families.",
            f"Beam width capped at {stage_beam} candidate states for this execution.",
        ],
    )
    result.artifacts["candidate_count"] = len(ranked)
    return result
