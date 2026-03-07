from __future__ import annotations

import unittest

from kryptos.common import (
    analyze_layered_candidate,
    bifid_encrypt,
    decrypt_bifid,
    encrypt_vigenere_standard,
    fractionation_candidate_score,
    generate_polybius_square,
    infer_repeating_vigenere_key,
)
from kryptos.constants import KNOWN_PLAINTEXT_CLUES
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import keyword_permutation, periodic_transposition_encrypt
from strategy12_periodic_transposition_hillclimb import search_periodic_candidates


def build_synthetic_plaintext() -> str:
    chars = ["X"] * 97
    for clue, details in KNOWN_PLAINTEXT_CLUES.items():
        start = int(details["start_index"]) - 1
        chars[start:start + len(clue)] = list(clue)
    return "".join(chars)


class FractionationLayerTests(unittest.TestCase):
    def test_anchor_consistent_key_is_recovered(self) -> None:
        plaintext = build_synthetic_plaintext()
        shifted = encrypt_vigenere_standard(plaintext, "LAYER")
        self.assertEqual(infer_repeating_vigenere_key(shifted, 5), "LAYER")

    def test_layered_analysis_beats_noise(self) -> None:
        plaintext = build_synthetic_plaintext()
        shifted = encrypt_vigenere_standard(plaintext, "LAYER")
        analysis = analyze_layered_candidate(shifted, max_key_length=8)
        self.assertEqual(analysis["mode"], "post_vigenere")
        self.assertEqual(analysis["derived_key"], "LAYER")
        self.assertEqual(set(analysis["matched_clues"]), set(KNOWN_PLAINTEXT_CLUES))
        self.assertGreater(int(analysis["score"]), fractionation_candidate_score(shifted))

    def test_bifid_then_vigenere_layer_round_trip(self) -> None:
        plaintext = build_synthetic_plaintext()
        shifted = encrypt_vigenere_standard(plaintext, "LAYER")
        square = generate_polybius_square("KRYPTOS")
        ciphertext = bifid_encrypt(7, shifted, square)
        bifid_stage = decrypt_bifid(7, ciphertext, square)
        analysis = analyze_layered_candidate(bifid_stage, max_key_length=8)
        self.assertEqual(bifid_stage, shifted)
        self.assertEqual(analysis["derived_key"], "LAYER")
        self.assertIn("EASTNORTHEAST", analysis["plaintext"])
        self.assertIn("BERLINCLOCK", analysis["plaintext"])

    def test_three_stage_round_trip(self) -> None:
        plaintext = build_synthetic_plaintext()
        shifted = encrypt_vigenere_standard(plaintext, "LAYER")
        permutation = keyword_permutation("KRYPTOS", 7)
        transposed = periodic_transposition_encrypt(shifted, 7, permutation)
        square = generate_polybius_square("KRYPTOS")
        ciphertext = bifid_encrypt(7, transposed, square)
        bifid_stage = decrypt_bifid(7, ciphertext, square)
        config = StrategyRuntimeConfig(candidate_limit=4, width_min=7, width_max=7)
        periodic_candidates, _attempts = search_periodic_candidates(bifid_stage, config)
        shifted_candidate = next(candidate for candidate in periodic_candidates[:4] if candidate["plaintext"] == shifted)
        layered = analyze_layered_candidate(str(shifted_candidate["plaintext"]), max_key_length=8)
        self.assertEqual(layered["derived_key"], "LAYER")


if __name__ == "__main__":
    unittest.main()