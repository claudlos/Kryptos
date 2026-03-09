from __future__ import annotations

import argparse
import unittest

from gpu_opencl_suite import (
    build_raw_candidate_entry,
    resolve_profile_config,
    select_candidates_for_hydration,
    sort_raw_candidate_entries,
)


class GpuOpenClTests(unittest.TestCase):
    def test_resolve_profile_config_clamps_gpu_pruning(self) -> None:
        args = argparse.Namespace(
            profile="smoke",
            dictionary="k4_dictionary.txt",
            passes=None,
            continuous=False,
            sweeps_per_pass=None,
            copies_per_sweep=None,
            match_limit=5,
            score_threshold=None,
            top_candidates=8,
            hydrate_limit=2,
            min_anchor_hits=99,
            max_post_key_length=50,
            json=False,
            output=None,
        )
        config = resolve_profile_config(args)
        self.assertEqual(config["top_candidate_limit"], 5)
        self.assertEqual(config["hydrate_limit"], 5)
        self.assertEqual(config["min_anchor_hits"], 24)
        self.assertEqual(config["max_post_key_length"], 12)

    def test_raw_candidate_entry_tracks_gpu_hint_fields(self) -> None:
        entry = build_raw_candidate_entry(
            raw_gid=42,
            sweep_index=3,
            raw_score=1770,
            exact_match=False,
            plaintext_hash=12345,
            anchor_hits=6,
            context_hits=2,
            language_hint=180,
            ngram_hint=135,
            periodic_hint=225,
            displacement_hint=310,
            best_displacement=-7,
            layer_hint=420,
        )
        self.assertEqual(entry["ngram_hint"], 135)
        self.assertEqual(entry["periodic_hint"], 225)
        self.assertEqual(entry["displacement_hint"], 310)
        self.assertEqual(entry["best_displacement"], -7)
        self.assertEqual(entry["layer_hint"], 420)

    def test_hydration_selection_prefers_structural_candidates(self) -> None:
        entries = [
            {
                "raw_gid": 1,
                "sweep_index": 0,
                "raw_score": 1450,
                "exact_match": False,
                "plaintext_hash": 11,
                "anchor_hits": 5,
                "context_hits": 1,
                "language_hint": 180,
                "ngram_hint": 60,
                "periodic_hint": 80,
                "displacement_hint": 70,
                "best_displacement": -10,
                "layer_hint": 220,
            },
            {
                "raw_gid": 2,
                "sweep_index": 0,
                "raw_score": 1450,
                "exact_match": False,
                "plaintext_hash": 11,
                "anchor_hits": 5,
                "context_hits": 1,
                "language_hint": 180,
                "ngram_hint": 120,
                "periodic_hint": 90,
                "displacement_hint": 150,
                "best_displacement": -5,
                "layer_hint": 210,
            },
            {
                "raw_gid": 3,
                "sweep_index": 0,
                "raw_score": 1410,
                "exact_match": True,
                "plaintext_hash": 21,
                "anchor_hits": 4,
                "context_hits": 0,
                "language_hint": 120,
                "ngram_hint": 0,
                "periodic_hint": 0,
                "displacement_hint": 0,
                "best_displacement": 0,
                "layer_hint": 180,
            },
            {
                "raw_gid": 4,
                "sweep_index": 0,
                "raw_score": 1450,
                "exact_match": False,
                "plaintext_hash": 31,
                "anchor_hits": 7,
                "context_hits": 2,
                "language_hint": 210,
                "ngram_hint": 40,
                "periodic_hint": 260,
                "displacement_hint": 260,
                "best_displacement": 8,
                "layer_hint": 260,
            },
        ]

        sorted_entries = sort_raw_candidate_entries(entries)
        self.assertEqual(sorted_entries[0]["raw_gid"], 3)
        self.assertEqual(sorted_entries[1]["raw_gid"], 4)
        self.assertEqual(sorted_entries[2]["raw_gid"], 2)

        selected = select_candidates_for_hydration(entries, hydrate_limit=3)
        self.assertEqual(len(selected), 3)
        self.assertEqual(selected[0]["raw_gid"], 3)
        self.assertEqual(selected[1]["raw_gid"], 4)
        self.assertEqual(selected[2]["raw_gid"], 2)
        self.assertEqual(sum(1 for candidate in selected if candidate["plaintext_hash"] == 11), 1)

    def test_displacement_hint_breaks_structural_ties_before_periodic_hint(self) -> None:
        entries = [
            {
                "raw_gid": 10,
                "sweep_index": 0,
                "raw_score": 1710,
                "exact_match": False,
                "plaintext_hash": 101,
                "anchor_hits": 5,
                "context_hits": 2,
                "language_hint": 180,
                "ngram_hint": 120,
                "periodic_hint": 210,
                "displacement_hint": 140,
                "best_displacement": -6,
                "layer_hint": 220,
            },
            {
                "raw_gid": 11,
                "sweep_index": 0,
                "raw_score": 1710,
                "exact_match": False,
                "plaintext_hash": 102,
                "anchor_hits": 5,
                "context_hits": 2,
                "language_hint": 180,
                "ngram_hint": 120,
                "periodic_hint": 260,
                "displacement_hint": 80,
                "best_displacement": 12,
                "layer_hint": 220,
            },
        ]

        sorted_entries = sort_raw_candidate_entries(entries)
        self.assertEqual(sorted_entries[0]["raw_gid"], 10)
        self.assertEqual(sorted_entries[1]["raw_gid"], 11)

    def test_resolve_profile_config_applies_adaptive_gpu_budget(self) -> None:
        args = argparse.Namespace(
            profile="smoke",
            dictionary="k4_dictionary.txt",
            passes=None,
            continuous=False,
            sweeps_per_pass=None,
            copies_per_sweep=None,
            match_limit=12,
            score_threshold=1500,
            top_candidates=3,
            hydrate_limit=4,
            min_anchor_hits=4,
            max_post_key_length=8,
            ledger_input="runs/research_ledger.json",
            ledger_output=None,
            json=False,
            output=None,
        )
        guidance = {
            "enabled": True,
            "preferred_stage_families": ["periodic_transposition", "key-layer", "bifid"],
        }
        config = resolve_profile_config(args, adaptive_guidance=guidance)
        self.assertEqual(config["hydrate_limit"], 9)
        self.assertEqual(config["top_candidate_limit"], 6)
        self.assertEqual(config["score_threshold"], 1460)
        self.assertEqual(config["adaptive_hydrate_bonus"], 5)
        self.assertEqual(config["adaptive_top_candidate_bonus"], 3)
        self.assertEqual(config["adaptive_threshold_delta"], 40)


if __name__ == "__main__":
    unittest.main()
