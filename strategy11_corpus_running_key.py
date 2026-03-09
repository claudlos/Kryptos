from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import anchor_component_score, build_ranked_candidate, build_strategy_result, decrypt_vigenere_standard, sort_ranked_candidates
from kryptos.constants import K4
from kryptos.runtime import StrategyRuntimeConfig

SPEC = get_strategy_spec("11")
RUNNING_KEY_DOCUMENTS = ("official", "carter")


def resolve_running_key_shortlist_limit(config: StrategyRuntimeConfig, coarse_count: int) -> int:
    return config.budgeted_limit(
        max(config.candidate_limit * 16, 32),
        family="running_key",
        max_extra=max(config.candidate_limit * 2, 8),
        ceiling=coarse_count,
    )


def generate_running_key_candidates(
    ciphertext: str = K4,
    config: StrategyRuntimeConfig | None = None,
    document_ids: tuple[str, ...] = RUNNING_KEY_DOCUMENTS,
) -> tuple[list[dict[str, object]], int]:
    config = config or StrategyRuntimeConfig()
    document_ids = config.ordered_documents(document_ids)
    coarse: list[tuple[int, dict[str, object]]] = []
    attempts = 0
    for window in config.corpora.iter_windows(len(ciphertext), document_ids=document_ids):
        attempts += 1
        plaintext = decrypt_vigenere_standard(ciphertext, str(window["window"]))
        coarse.append(
            (
                anchor_component_score(plaintext),
                {
                    "plaintext": plaintext,
                    "document_id": str(window["document_id"]),
                    "offset": int(window["offset"]),
                },
            )
        )
    shortlist_limit = resolve_running_key_shortlist_limit(config, len(coarse))
    shortlisted = sorted(coarse, key=lambda item: item[0], reverse=True)[:shortlist_limit]
    candidates = [
        build_ranked_candidate(
            item["plaintext"],
            transform_chain=[f"running_key:{item['document_id']}:offset={item['offset']}"],
            corpus_bundle=config.corpora,
            scorer_profile=config.scorer_profile,
            key_material={"offset": item["offset"], "window_length": len(ciphertext)},
            corpus_id=item["document_id"],
            structure_hint=220,
        )
        for _score, item in shortlisted
    ]
    return sort_ranked_candidates(candidates), attempts


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    candidates, attempts = generate_running_key_candidates(config=config)
    retained = candidates[: max(config.candidate_limit, 8)]
    ordered_documents = config.ordered_documents(RUNNING_KEY_DOCUMENTS)
    coarse_count = sum(max(len(document.normalized_text) - len(K4) + 1, 0) for document in config.corpora.select_documents(ordered_documents))
    notes = [
        f"Scanned public corpus windows from: {', '.join(ordered_documents)} and retained a shortlist of {resolve_running_key_shortlist_limit(config, coarse_count)} windows for full reranking.",
        "Used anchor alignment as a fast prefilter before full corpus-aware scoring.",
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
