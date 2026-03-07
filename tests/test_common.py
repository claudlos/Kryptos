from __future__ import annotations

import unittest

from kryptos.common import bifid_encrypt, build_score_breakdown, decrypt_bifid, generate_polybius_square
from kryptos.constants import ANCHOR_COMPONENT_CLUES, K4, KNOWN_PLAINTEXT_CLUES


class CommonCryptoTests(unittest.TestCase):
    def test_k4_length_and_anchor_positions(self) -> None:
        self.assertEqual(len(K4), 97)
        for plaintext, details in KNOWN_PLAINTEXT_CLUES.items():
            start = int(details["start_index"]) - 1
            ciphertext = str(details["ciphertext"])
            self.assertEqual(K4[start:start + len(ciphertext)], ciphertext)
            self.assertGreaterEqual(int(details["end_index"]), int(details["start_index"]))
        for plaintext, details in ANCHOR_COMPONENT_CLUES.items():
            start = int(details["start_index"]) - 1
            ciphertext = str(details["ciphertext"])
            self.assertEqual(K4[start:start + len(ciphertext)], ciphertext)

    def test_polybius_square_is_25_unique_letters(self) -> None:
        square = generate_polybius_square("KRYPTOS")
        self.assertEqual(len(square), 25)
        self.assertEqual(len(set(square)), 25)
        self.assertNotIn("J", square)

    def test_bifid_round_trip(self) -> None:
        square = generate_polybius_square("KRYPTOS")
        plaintext = "WEAREDISCOVERED"
        ciphertext = bifid_encrypt(5, plaintext, square)
        decrypted = decrypt_bifid(5, ciphertext, square)
        self.assertEqual(decrypted, plaintext)

    def test_score_breakdown_schema(self) -> None:
        breakdown = build_score_breakdown("EASTNORTHEASTXXXXBERLINCLOCK")
        self.assertEqual(
            sorted(breakdown),
            ["anchor", "domain", "entity", "language", "penalty", "structure", "total"],
        )
        self.assertLessEqual(breakdown["total"], 1000)


if __name__ == "__main__":
    unittest.main()