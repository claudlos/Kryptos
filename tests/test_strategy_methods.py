from __future__ import annotations

import importlib
import tempfile
import unittest
from pathlib import Path

from kryptos.common import build_displacement_route_candidates, build_score_breakdown, encrypt_vigenere_standard, rotate_text
from kryptos.corpora import load_corpus_profile
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import keyword_permutation, periodic_transposition_encrypt
from strategy10_fractionation import generate_fractionation_candidates
from strategy11_corpus_running_key import generate_running_key_candidates
from strategy12_periodic_transposition_hillclimb import search_periodic_candidates
from strategy32_unknown_source_running_key import generate_unknown_source_running_key_candidates
from strategy37_transposition_unknown_source_running_key import generate_transposition_running_key_candidates


def build_synthetic_plaintext() -> str:
    chars = ["X"] * 97
    chars[21:34] = list("EASTNORTHEAST")
    chars[63:74] = list("BERLINCLOCK")
    chars[75:82] = list("MESSAGE")
    return "".join(chars)


class StrategyMethodTests(unittest.TestCase):
    def test_running_key_regression_recovers_carter_window(self) -> None:
        bundle = load_corpus_profile("carter")
        carter_text = bundle.select_documents(("carter",))[0].normalized_text
        offset = 0
        key_window = carter_text[offset:offset + 97]
        plaintext = build_synthetic_plaintext()
        ciphertext = encrypt_vigenere_standard(plaintext, key_window)
        config = StrategyRuntimeConfig(dataset_profile="carter", candidate_limit=4)
        candidates, _attempts = generate_running_key_candidates(ciphertext, config, document_ids=("carter",))
        exact = next(candidate for candidate in candidates[:3] if candidate["plaintext"] == plaintext)
        self.assertEqual(exact["corpus_id"], "carter")
        self.assertEqual(exact["key_material"]["offset"], offset)
        self.assertGreaterEqual(exact["total_score"], 400)

    def test_periodic_transposition_regression_recovers_keyword_family(self) -> None:
        plaintext = build_synthetic_plaintext()
        permutation = keyword_permutation("KRYPTOS", 7)
        ciphertext = periodic_transposition_encrypt(plaintext, 7, permutation)
        baseline = build_score_breakdown(ciphertext)["language"]
        config = StrategyRuntimeConfig(candidate_limit=4, width_min=7, width_max=7)
        candidates, _attempts = search_periodic_candidates(ciphertext, config)
        top = candidates[0]
        self.assertEqual(top["plaintext"], plaintext)
        self.assertEqual(top["key_material"]["width"], 7)
        self.assertGreater(top["total_score"], baseline)

    def test_unknown_source_running_key_regression_recovers_local_window(self) -> None:
        plaintext = build_synthetic_plaintext()
        prefix = "ARCHIVEENTRY"
        filler = "REFERENCEBLOCK" * 20
        normalized_source = prefix + plaintext + filler
        key_window = normalized_source[:97]
        ciphertext = encrypt_vigenere_standard(plaintext, key_window)
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = Path(temp_dir) / "synthetic_source.txt"
            source_path.write_text(normalized_source, encoding="utf-8")
            config = StrategyRuntimeConfig(dataset_profile="public", candidate_limit=4)
            candidates, _attempts, sources = generate_unknown_source_running_key_candidates(
                ciphertext,
                config,
                repo_source_paths=(),
                include_repo_texts=False,
                include_corpora=False,
                include_solved_panels=False,
                extra_source_paths=(str(source_path),),
            )
        exact = next(candidate for candidate in candidates if candidate["plaintext"] == plaintext)
        self.assertEqual(exact["key_material"]["offset"], 0)
        self.assertEqual(exact["key_material"]["source_path"], str(source_path))
        self.assertEqual(sources[0]["normalized_length"], len(normalized_source))

    def test_unknown_source_running_key_default_pool_includes_corpora_and_solved_panels(self) -> None:
        config = StrategyRuntimeConfig(dataset_profile="public", candidate_limit=2)
        _candidates, _attempts, sources = generate_unknown_source_running_key_candidates(config=config)
        source_kinds = {entry["source_kind"] for entry in sources}
        self.assertIn("repo-text", source_kinds)
        self.assertIn("corpus:historical", source_kinds)
        self.assertIn("solved-panel", source_kinds)

    def test_transposition_running_key_regression_recovers_synthetic_pipeline(self) -> None:
        plaintext = build_synthetic_plaintext()
        permutation = keyword_permutation("KRYPTOS", 7)
        pre_transposition = encrypt_vigenere_standard(plaintext, plaintext)
        ciphertext = periodic_transposition_encrypt(pre_transposition, 7, permutation)
        normalized_source = plaintext + ("REFERENCEBLOCK" * 20)
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path = Path(temp_dir) / "synthetic_source.txt"
            source_path.write_text(normalized_source, encoding="utf-8")
            config = StrategyRuntimeConfig(dataset_profile="public", candidate_limit=4)
            candidates, _attempts, _sources, _transpositions = generate_transposition_running_key_candidates(
                ciphertext,
                config,
                transposition_configs=[
                    {
                        "label": "KRYPTOS:w7",
                        "width": 7,
                        "permutation": permutation,
                        "keyword": "KRYPTOS",
                    }
                ],
                include_repo_texts=False,
                include_corpora=False,
                include_solved_panels=False,
                extra_source_paths=(str(source_path),),
            )
        exact = next(candidate for candidate in candidates if candidate["plaintext"] == plaintext)
        self.assertEqual(exact["key_material"]["transposition_label"], "KRYPTOS:w7")
        self.assertEqual(exact["key_material"]["source_path"], str(source_path))

    def test_geo_route_reranker_prefers_clue_rich_candidate(self) -> None:
        bundle = load_corpus_profile("geo")
        geo_candidate = build_synthetic_plaintext() + "BERLINWORLDCLOCKMESSAGE"
        generic_candidate = "THEROOMWITHLIGHTANDSOMESTRUCTURE" * 4
        geo_score = build_score_breakdown(geo_candidate, corpus_bundle=bundle, scorer_profile="geo-route")["total"]
        generic_score = build_score_breakdown(generic_candidate[: len(geo_candidate)], corpus_bundle=bundle, scorer_profile="geo-route")["total"]
        self.assertGreater(geo_score, generic_score)

    def test_displacement_route_followup_realigns_shifted_anchor_candidate(self) -> None:
        bundle = load_corpus_profile("geo")
        plaintext = build_synthetic_plaintext()
        shifted = rotate_text(plaintext, 5)
        candidates = build_displacement_route_candidates(
            shifted,
            transform_chain=["direct"],
            corpus_bundle=bundle,
            scorer_profile="anchor-first",
            displacement_window=8,
            route_followup_limit=2,
            preferred_deltas=(-5,),
        )
        top = candidates[0]
        self.assertEqual(top["plaintext"], plaintext)
        self.assertEqual(top["key_material"]["displacement_delta"], -5)
        self.assertGreater(top["geo_route_total"], 0)

    def test_shared_stage_cache_preserves_hybrid_top_candidate(self) -> None:
        config = StrategyRuntimeConfig(
            dataset_profile="public",
            scorer_profile="anchor-first",
            beam_width=8,
            candidate_limit=2,
            max_post_key_length=4,
            width_min=7,
            width_max=7,
            displacement_window=8,
            route_followup_limit=2,
        )
        fresh_config = StrategyRuntimeConfig(
            dataset_profile="public",
            scorer_profile="anchor-first",
            beam_width=8,
            candidate_limit=2,
            max_post_key_length=4,
            width_min=7,
            width_max=7,
            displacement_window=8,
            route_followup_limit=2,
        )
        fresh_result = importlib.import_module("strategy13_hybrid_pipeline_search").run(fresh_config)

        fractionation_candidates, fractionation_attempts = generate_fractionation_candidates(config=config)
        cached_fractionation_candidates, cached_fractionation_attempts = generate_fractionation_candidates(config=config)
        self.assertGreater(fractionation_attempts, 0)
        self.assertEqual(cached_fractionation_attempts, 0)
        self.assertEqual(cached_fractionation_candidates[0]["plaintext"], fractionation_candidates[0]["plaintext"])

        running_candidates, running_attempts = generate_running_key_candidates(config=config)
        cached_running_candidates, cached_running_attempts = generate_running_key_candidates(config=config)
        self.assertGreater(running_attempts, 0)
        self.assertEqual(cached_running_attempts, 0)
        self.assertEqual(cached_running_candidates[0]["plaintext"], running_candidates[0]["plaintext"])

        periodic_candidates, periodic_attempts = search_periodic_candidates(config=config)
        cached_periodic_candidates, cached_periodic_attempts = search_periodic_candidates(config=config)
        self.assertGreater(periodic_attempts, 0)
        self.assertEqual(cached_periodic_attempts, 0)
        self.assertEqual(cached_periodic_candidates[0]["plaintext"], periodic_candidates[0]["plaintext"])

        warmed_result = importlib.import_module("strategy13_hybrid_pipeline_search").run(config)
        self.assertEqual(running_candidates[0]["rank"], 1)
        self.assertEqual(periodic_candidates[0]["rank"], 1)
        self.assertEqual(
            warmed_result.artifacts["top_candidates"][0]["plaintext"],
            fresh_result.artifacts["top_candidates"][0]["plaintext"],
        )
        self.assertEqual(
            warmed_result.artifacts["top_candidates"][0]["total_score"],
            fresh_result.artifacts["top_candidates"][0]["total_score"],
        )

    def test_new_strategies_return_retained_candidates_on_smoke(self) -> None:
        config = StrategyRuntimeConfig(
            dataset_profile="public",
            scorer_profile="anchor-first",
            beam_width=16,
            candidate_limit=2,
            max_post_key_length=8,
            width_min=7,
            width_max=8,
            displacement_window=8,
            route_followup_limit=2,
        )
        for module_name in (
            "strategy10_fractionation",
            "strategy11_corpus_running_key",
            "strategy12_periodic_transposition_hillclimb",
            "strategy13_hybrid_pipeline_search",
            "strategy14_displacement_route_search",
            "strategy32_unknown_source_running_key",
            "strategy37_transposition_unknown_source_running_key",
        ):
            module = importlib.import_module(module_name)
            result = module.run(config)
            self.assertTrue(result.artifacts["top_candidates"], module_name)
            self.assertEqual(result.artifacts["top_candidates"][0]["rank"], 1)


if __name__ == "__main__":
    unittest.main()
