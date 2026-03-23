from __future__ import annotations

from pathlib import Path

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    anchor_component_score,
    build_ranked_candidate,
    build_strategy_result,
    dedupe_ranked_candidates,
    decrypt_vigenere_standard,
)
from kryptos.constants import K4
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.source_material import REPO_SOURCE_FILES, load_all_running_key_sources, summarize_sources

SPEC = get_strategy_spec("32")
CORPUS_DOCUMENT_IDS = ("official", "carter", "berlin_geo")


def generate_unknown_source_running_key_candidates(
    ciphertext: str = K4,
    config: StrategyRuntimeConfig | None = None,
    *,
    repo_source_paths: tuple[str, ...] = REPO_SOURCE_FILES,
    corpus_document_ids: tuple[str, ...] = CORPUS_DOCUMENT_IDS,
    include_repo_texts: bool = True,
    include_corpora: bool = True,
    include_solved_panels: bool = True,
    extra_source_paths: tuple[str, ...] = (),
) -> tuple[list[dict[str, object]], int, list[dict[str, object]]]:
    config = config or StrategyRuntimeConfig()
    cache_key = config.stage_cache_key(
        "unknown-source-running-key",
        ciphertext,
        tuple(repo_source_paths),
        tuple(corpus_document_ids),
        include_repo_texts,
        include_corpora,
        include_solved_panels,
        tuple(extra_source_paths),
    )
    cached = config.get_stage_cache(cache_key)
    if cached is not None:
        cached_candidates, cached_sources = cached
        return list(cached_candidates), 0, list(cached_sources)

    sources = load_all_running_key_sources(
        config,
        repo_source_paths=repo_source_paths,
        corpus_document_ids=corpus_document_ids,
        include_repo_texts=include_repo_texts,
        include_corpora=include_corpora,
        include_solved_panels=include_solved_panels,
        extra_source_paths=extra_source_paths,
    )
    coarse: list[tuple[int, dict[str, object]]] = []
    attempts = 0
    for source in sources:
        normalized_text = str(source["normalized_text"])
        source_id = str(source["source_id"])
        source_kind = str(source["source_kind"])
        source_path = str(source.get("source_path") or source_id)
        if len(normalized_text) < len(ciphertext):
            continue
        for offset in range(len(normalized_text) - len(ciphertext) + 1):
            attempts += 1
            key_window = normalized_text[offset:offset + len(ciphertext)]
            plaintext = decrypt_vigenere_standard(ciphertext, key_window)
            coarse.append(
                (
                    anchor_component_score(plaintext),
                    {
                        "plaintext": plaintext,
                        "source_id": source_id,
                        "source_kind": source_kind,
                        "source_path": source_path,
                        "offset": offset,
                        "window_length": len(ciphertext),
                    },
                )
            )

    shortlist_size = max(config.candidate_limit * 24, 64)
    shortlisted = sorted(coarse, key=lambda item: item[0], reverse=True)[:shortlist_size]
    candidates = [
        build_ranked_candidate(
            item["plaintext"],
            transform_chain=[f"running_key_source:{item['source_id']}:offset={item['offset']}"],
            corpus_bundle=config.corpora,
            scorer_profile="running-key",
            key_material={
                "offset": item["offset"],
                "window_length": item["window_length"],
                "source_id": item["source_id"],
                "source_kind": item["source_kind"],
                "source_path": item["source_path"],
            },
            corpus_id=item["source_id"],
            structure_hint=240,
        )
        for _score, item in shortlisted
    ]
    ranked = dedupe_ranked_candidates(candidates)
    source_metadata = summarize_sources(sources)
    config.set_stage_cache(cache_key, (tuple(ranked), tuple(source_metadata)))
    return ranked, attempts, source_metadata


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    candidates, attempts, source_metadata = generate_unknown_source_running_key_candidates(config=config)
    retained = candidates[: max(config.candidate_limit, 8)]
    result = build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=[
            f"Scanned normalized 97-character running-key windows from {len(source_metadata)} mixed sources.",
            "Source set now includes repo-local notes, packaged corpus documents, and solved-panel plaintext references.",
            "This targets the handoff hypothesis that K4 may use an unknown running key derived from adjacent text rather than only the original public corpus bundle.",
        ],
    )
    result.artifacts["candidate_count"] = len(candidates)
    result.artifacts["source_files"] = source_metadata
    return result
