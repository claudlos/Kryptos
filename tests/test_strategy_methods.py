from __future__ import annotations

import importlib
import unittest

from kryptos.common import build_score_breakdown, encrypt_vigenere_standard
from kryptos.corpora import load_corpus_profile
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import keyword_permutation, periodic_transposition_encrypt
from strategy11_corpus_running_key import generate_running_key_candidates
from strategy12_periodic_transposition_hillclimb import search_periodic_candidates


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

    def test_geo_route_reranker_prefers_clue_rich_candidate(self) -> None:
        bundle = load_corpus_profile("geo")
        geo_candidate = build_synthetic_plaintext() + "BERLINWORLDCLOCKMESSAGE"
        generic_candidate = "THEROOMWITHLIGHTANDSOMESTRUCTURE" * 4
        geo_score = build_score_breakdown(geo_candidate, corpus_bundle=bundle, scorer_profile="geo-route")["total"]
        generic_score = build_score_breakdown(generic_candidate[: len(geo_candidate)], corpus_bundle=bundle, scorer_profile="geo-route")["total"]
        self.assertGreater(geo_score, generic_score)

    def test_new_strategies_return_retained_candidates_on_smoke(self) -> None:
        config = StrategyRuntimeConfig(dataset_profile="public", scorer_profile="anchor-first", beam_width=16, candidate_limit=2, width_max=8, max_post_key_length=8)
        for module_name in (
            "strategy10_fractionation",
            "strategy11_corpus_running_key",
            "strategy12_periodic_transposition_hillclimb",
            "strategy13_hybrid_pipeline_search",
        ):
            module = importlib.import_module(module_name)
            result = module.run(config)
            self.assertTrue(result.artifacts["top_candidates"], module_name)
            self.assertEqual(result.artifacts["top_candidates"][0]["rank"], 1)


if __name__ == "__main__":
    unittest.main()