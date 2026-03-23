from __future__ import annotations

import argparse
import unittest

from gpu_opencl_suite import (
    allocate_focus_budgets,
    build_raw_candidate_entry,
    dedupe_candidate_records,
    iter_local_swap_variants,
    merge_top_raw_candidates,
    resolve_work_sizes,
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
            local_size=None,
            focus_budget=None,
            focus_seed_limit=None,
            focus_neighbor_span=None,
            json=False,
            output=None,
        )
        config = resolve_profile_config(args)
        self.assertEqual(config["top_candidate_limit"], 5)
        self.assertEqual(config["hydrate_limit"], 5)
        self.assertEqual(config["min_anchor_hits"], 24)
        self.assertEqual(config["max_post_key_length"], 12)

    def test_resolve_profile_config_keeps_local_size_override(self) -> None:
        args = argparse.Namespace(
            profile="smoke",
            dictionary="k4_dictionary.txt",
            passes=None,
            continuous=False,
            sweeps_per_pass=None,
            copies_per_sweep=None,
            match_limit=None,
            score_threshold=None,
            top_candidates=None,
            hydrate_limit=None,
            min_anchor_hits=None,
            max_post_key_length=None,
            local_size=64,
            focus_budget=None,
            focus_seed_limit=None,
            focus_neighbor_span=None,
            json=False,
            output=None,
        )
        config = resolve_profile_config(args)
        self.assertEqual(config["local_size"], 64)

    def test_resolve_profile_config_keeps_focus_overrides(self) -> None:
        args = argparse.Namespace(
            profile="smoke",
            dictionary="k4_dictionary.txt",
            passes=None,
            continuous=False,
            sweeps_per_pass=None,
            copies_per_sweep=None,
            match_limit=None,
            score_threshold=None,
            top_candidates=None,
            hydrate_limit=None,
            min_anchor_hits=None,
            max_post_key_length=None,
            local_size=None,
            focus_budget=11,
            focus_seed_limit=3,
            focus_neighbor_span=2,
            json=False,
            output=None,
        )
        config = resolve_profile_config(args)
        self.assertEqual(config["focus_budget"], 11)
        self.assertEqual(config["focus_seed_limit"], 3)
        self.assertEqual(config["focus_neighbor_span"], 2)

    def test_resolve_work_sizes_rounds_global_to_local_multiple(self) -> None:
        class KernelStub:
            def get_work_group_info(self, _info: object, _device: object) -> int:
                return 256

        class DeviceStub:
            max_work_group_size = 256
            name = "stub-gpu"

        global_shape, local_shape = resolve_work_sizes(1000, 64, device=DeviceStub(), kernel=KernelStub())
        self.assertEqual(global_shape, (1024,))
        self.assertEqual(local_shape, (64,))

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

    def test_candidate_record_deduping_keeps_best_family_preview_match(self) -> None:
        records = [
            {
                "exact_match": False,
                "matched_clues": [],
                "best_score": 320,
                "geo_route_total": 280,
                "raw_displacement_hint": 120,
                "raw_periodic_hint": 90,
                "raw_ngram_hint": 60,
                "raw_anchor_hits": 5,
                "raw_context_hits": 1,
                "raw_score": 1800,
                "transform_chain": ["direct", "displacement:delta=-5"],
                "best_preview": "EASTCANDIDATE",
            },
            {
                "exact_match": False,
                "matched_clues": [],
                "best_score": 300,
                "geo_route_total": 240,
                "raw_displacement_hint": 90,
                "raw_periodic_hint": 90,
                "raw_ngram_hint": 60,
                "raw_anchor_hits": 5,
                "raw_context_hits": 1,
                "raw_score": 1700,
                "transform_chain": ["direct", "displacement:delta=-7"],
                "best_preview": "EASTCANDIDATE",
            },
            {
                "exact_match": False,
                "matched_clues": [],
                "best_score": 315,
                "geo_route_total": 275,
                "raw_displacement_hint": 95,
                "raw_periodic_hint": 120,
                "raw_ngram_hint": 80,
                "raw_anchor_hits": 5,
                "raw_context_hits": 1,
                "raw_score": 1750,
                "transform_chain": ["direct", "post_periodic_transposition:w9:row->column"],
                "best_preview": "EASTCANDIDATE",
            },
        ]
        deduped = dedupe_candidate_records(records)
        self.assertEqual(len(deduped), 2)
        self.assertEqual(deduped[0]["best_score"], 320)
        self.assertEqual(deduped[1]["transform_chain"][1], "post_periodic_transposition:w9:row->column")

    def test_allocate_focus_budgets_prefers_stronger_seed(self) -> None:
        records = [
            {
                "best_score": 320,
                "geo_route_total": 40,
                "raw_displacement_hint": 120,
                "raw_periodic_hint": 80,
                "matched_clues": ["EAST"],
                "exact_match": False,
                "raw_anchor_hits": 5,
                "raw_context_hits": 1,
                "raw_score": 1800,
            },
            {
                "best_score": 250,
                "geo_route_total": 0,
                "raw_displacement_hint": 10,
                "raw_periodic_hint": 20,
                "matched_clues": [],
                "exact_match": False,
                "raw_anchor_hits": 4,
                "raw_context_hits": 0,
                "raw_score": 1600,
            },
        ]
        plans = allocate_focus_budgets(records, total_budget=5, seed_limit=2)
        self.assertEqual(len(plans), 2)
        self.assertEqual(sum(int(plan["budget"]) for plan in plans), 5)
        self.assertGreaterEqual(int(plans[0]["budget"]), int(plans[1]["budget"]))

    def test_iter_local_swap_variants_is_bounded_and_unique(self) -> None:
        variants = iter_local_swap_variants("ABCDEFGHIKLMNOPQRSTUVWXYZ", limit=6, span=2)
        self.assertEqual(len(variants), 6)
        self.assertEqual(len({square for square, _labels in variants}), 6)

    def test_merge_top_raw_candidates_keeps_best_scoring_survivors(self) -> None:
        existing = [
            build_raw_candidate_entry(
                raw_gid=1,
                sweep_index=0,
                raw_score=1400,
                exact_match=False,
                plaintext_hash=0,
                anchor_hits=5,
                context_hits=0,
                language_hint=0,
                ngram_hint=0,
                periodic_hint=0,
                displacement_hint=20,
                best_displacement=0,
                layer_hint=0,
            )
        ]
        incoming = [
            build_raw_candidate_entry(
                raw_gid=2,
                sweep_index=0,
                raw_score=1800,
                exact_match=False,
                plaintext_hash=0,
                anchor_hits=6,
                context_hits=0,
                language_hint=0,
                ngram_hint=0,
                periodic_hint=0,
                displacement_hint=40,
                best_displacement=0,
                layer_hint=0,
            ),
            build_raw_candidate_entry(
                raw_gid=3,
                sweep_index=0,
                raw_score=1500,
                exact_match=False,
                plaintext_hash=0,
                anchor_hits=5,
                context_hits=0,
                language_hint=0,
                ngram_hint=0,
                periodic_hint=0,
                displacement_hint=10,
                best_displacement=0,
                layer_hint=0,
            ),
        ]
        merged = merge_top_raw_candidates(existing, incoming, max_entries=2)
        self.assertEqual(len(merged), 2)
        self.assertEqual(int(merged[0]["raw_gid"]), 2)
        self.assertEqual(int(merged[1]["raw_gid"]), 3)


if __name__ == "__main__":
    unittest.main()
