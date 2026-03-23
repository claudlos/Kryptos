from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    anchor_component_score,
    build_ranked_candidate,
    build_strategy_result,
    dedupe_ranked_candidates,
    decrypt_vigenere_standard,
)
from kryptos.constants import DEFAULT_KEYWORDS, K4
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.source_material import load_all_running_key_sources, summarize_sources
from kryptos.transposition import keyword_permutation, periodic_transposition_decrypt

SPEC = get_strategy_spec("37")
CORPUS_DOCUMENT_IDS = ("official", "carter", "berlin_geo")
BASE_TRANSPOSITION_KEYWORDS = ("LATITUDE", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK")


def build_transposition_configs() -> list[dict[str, object]]:
    configs: list[dict[str, object]] = [
        {"label": "LATITUDE:w6", "width": 6, "permutation": (1, 5, 3, 0, 2, 4), "keyword": "LATITUDE"},
    ]
    seen = {(6, (1, 5, 3, 0, 2, 4))}
    for keyword in (*BASE_TRANSPOSITION_KEYWORDS, *DEFAULT_KEYWORDS):
        for width in (6, 7, 8):
            permutation = tuple(keyword_permutation(keyword, width))
            signature = (width, permutation)
            if signature in seen:
                continue
            seen.add(signature)
            configs.append(
                {
                    "label": f"{keyword}:w{width}",
                    "width": width,
                    "permutation": permutation,
                    "keyword": keyword,
                }
            )
    return configs


def generate_transposition_running_key_candidates(
    ciphertext: str = K4,
    config: StrategyRuntimeConfig | None = None,
    *,
    corpus_document_ids: tuple[str, ...] = CORPUS_DOCUMENT_IDS,
    transposition_configs: list[dict[str, object]] | None = None,
    include_repo_texts: bool = True,
    include_corpora: bool = True,
    include_solved_panels: bool = True,
    extra_source_paths: tuple[str, ...] = (),
) -> tuple[list[dict[str, object]], int, list[dict[str, object]], list[dict[str, object]]]:
    config = config or StrategyRuntimeConfig()
    transposition_configs = transposition_configs or build_transposition_configs()
    cache_key = config.stage_cache_key(
        "transposition-running-key",
        ciphertext,
        tuple(corpus_document_ids),
        tuple((entry["label"], entry["width"], entry["permutation"]) for entry in transposition_configs),
        include_repo_texts,
        include_corpora,
        include_solved_panels,
        tuple(extra_source_paths),
    )
    cached = config.get_stage_cache(cache_key)
    if cached is not None:
        cached_candidates, cached_sources, cached_transpositions = cached
        return list(cached_candidates), 0, list(cached_sources), list(cached_transpositions)

    sources = load_all_running_key_sources(
        config,
        corpus_document_ids=corpus_document_ids,
        include_repo_texts=include_repo_texts,
        include_corpora=include_corpora,
        include_solved_panels=include_solved_panels,
        extra_source_paths=extra_source_paths,
    )
    coarse: list[tuple[int, dict[str, object]]] = []
    attempts = 0
    for transposition in transposition_configs:
        intermediate = periodic_transposition_decrypt(ciphertext, int(transposition["width"]), tuple(transposition["permutation"]))
        for source in sources:
            normalized_text = str(source["normalized_text"])
            if len(normalized_text) < len(ciphertext):
                continue
            for offset in range(len(normalized_text) - len(ciphertext) + 1):
                attempts += 1
                key_window = normalized_text[offset:offset + len(ciphertext)]
                plaintext = decrypt_vigenere_standard(intermediate, key_window)
                coarse.append(
                    (
                        anchor_component_score(plaintext),
                        {
                            "plaintext": plaintext,
                            "transposition": transposition,
                            "source_id": str(source["source_id"]),
                            "source_kind": str(source["source_kind"]),
                            "source_path": str(source.get("source_path") or source["source_id"]),
                            "offset": offset,
                        },
                    )
                )

    shortlist_size = max(config.candidate_limit * 32, 96)
    shortlisted = sorted(coarse, key=lambda item: item[0], reverse=True)[:shortlist_size]
    candidates = [
        build_ranked_candidate(
            item["plaintext"],
            transform_chain=[
                f"transposition:{item['transposition']['label']}",
                f"running_key_source:{item['source_id']}:offset={item['offset']}",
            ],
            corpus_bundle=config.corpora,
            scorer_profile=config.scorer_profile,
            key_material={
                "transposition_label": item["transposition"]["label"],
                "width": item["transposition"]["width"],
                "permutation": item["transposition"]["permutation"],
                "transposition_keyword": item["transposition"]["keyword"],
                "source_id": item["source_id"],
                "source_kind": item["source_kind"],
                "source_path": item["source_path"],
                "offset": item["offset"],
                "window_length": len(ciphertext),
            },
            corpus_id=item["source_id"],
            structure_hint=260,
        )
        for _score, item in shortlisted
    ]
    ranked = dedupe_ranked_candidates(candidates)
    source_metadata = summarize_sources(sources)
    transposition_metadata = [
        {
            "label": entry["label"],
            "keyword": entry["keyword"],
            "width": entry["width"],
            "permutation": list(entry["permutation"]),
        }
        for entry in transposition_configs
    ]
    config.set_stage_cache(cache_key, (tuple(ranked), tuple(source_metadata), tuple(transposition_metadata)))
    return ranked, attempts, source_metadata, transposition_metadata


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    candidates, attempts, source_metadata, transposition_metadata = generate_transposition_running_key_candidates(config=config)
    retained = candidates[: max(config.candidate_limit, 8)]
    result = build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=[
            f"Tested {len(transposition_metadata)} bounded transposition configurations against {len(source_metadata)} running-key sources.",
            "This is the combined LATITUDE/transposition + unknown-source running-key lane requested after the handoff.",
        ],
    )
    result.artifacts["candidate_count"] = len(candidates)
    result.artifacts["source_files"] = source_metadata
    result.artifacts["transposition_configs"] = transposition_metadata
    return result
