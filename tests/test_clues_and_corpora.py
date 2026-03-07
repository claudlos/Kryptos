from __future__ import annotations

import unittest
from pathlib import Path

from kryptos.catalog import anchor_catalog, clue_catalog
from kryptos.corpora import load_corpus_profile


class ClueAndCorpusTests(unittest.TestCase):
    def test_clue_taxonomy_contains_context_and_meta(self) -> None:
        clues = clue_catalog()
        labels = {str(entry.get("label") or entry.get("plaintext")) for entry in clues}
        self.assertIn("Egypt 1986", labels)
        self.assertIn("Fall of the Berlin Wall", labels)
        self.assertIn("World Clock", labels)
        self.assertIn("K5 uses a similar coding system", labels)
        anchors = anchor_catalog()
        anchor_labels = {str(entry["plaintext"]) for entry in anchors}
        self.assertIn("EAST", anchor_labels)
        self.assertIn("NORTHEAST", anchor_labels)
        self.assertIn("BERLINCLOCK", anchor_labels)

    def test_corpus_loader_uses_deterministic_fixture_fallback(self) -> None:
        bundle = load_corpus_profile("public")
        self.assertEqual(bundle.document_ids(), ("official", "carter", "berlin_geo"))
        metadata = bundle.metadata()
        self.assertTrue(all(bool(item["resolved_path"]) for item in metadata))
        self.assertTrue(all(Path(item["resolved_path"]).exists() for item in metadata))
        self.assertIn("ALEXANDERPLATZ", bundle.entity_terms)
        self.assertIn("MESSAGE", bundle.domain_terms)


if __name__ == "__main__":
    unittest.main()