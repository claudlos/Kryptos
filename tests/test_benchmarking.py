from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from kryptos.benchmark_cli import parse_mojo_markers
from kryptos.benchmarking import build_benchmark_comparison, get_benchmark_profile, list_profiles, list_runners


REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


class BenchmarkingTests(unittest.TestCase):
    def test_profile_catalog_contains_expected_runners(self) -> None:
        self.assertIn("cpu-strategy", list_runners())
        self.assertIn("gpu-opencl", list_runners())
        self.assertIn("default", list_profiles("cpu-strategy"))

    def test_profile_lookup(self) -> None:
        profile = get_benchmark_profile("cpu-strategy", "smoke")
        self.assertEqual(profile["beam_width"], 64)
        self.assertEqual(profile["candidate_limit"], 4)
        self.assertEqual(profile["width_max"], 12)
        self.assertEqual(profile["displacement_window"], 12)
        self.assertEqual(profile["route_followup_limit"], 2)
        self.assertIn("14", profile["strategy_ids"])

    def test_gpu_default_profile_is_tuned_for_pruning(self) -> None:
        profile = get_benchmark_profile("gpu-opencl", "default")
        self.assertEqual(profile["score_threshold"], 1700)
        self.assertEqual(profile["min_anchor_hits"], 5)
        self.assertEqual(profile["focus_budget"], 24)
        self.assertEqual(profile["focus_seed_limit"], 4)
        self.assertEqual(profile["focus_neighbor_span"], 2)

    def test_mojo_marker_parser(self) -> None:
        stdout = "\n".join(
            [
                "[BENCH] BENCHMARK_PROFILE=smoke",
                "[BENCH] BENCHMARK_TOTAL_ATTEMPTS=123",
                "[BENCH] BENCHMARK_UNIQUE_ATTEMPTS=120",
                "[BENCH] BENCHMARK_MATCHES=0",
            ]
        )
        markers = parse_mojo_markers(stdout)
        self.assertEqual(markers["PROFILE"], "smoke")
        self.assertEqual(markers["TOTAL_ATTEMPTS"], "123")
        self.assertEqual(markers["UNIQUE_ATTEMPTS"], "120")

    def test_cpu_plan_only_benchmark_command(self) -> None:
        completed = subprocess.run(
            [
                PYTHON,
                "-m",
                "kryptos.benchmark_cli",
                "--runner",
                "cpu-strategy",
                "--profile",
                "smoke",
                "--plan-only",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["runner"], "cpu-strategy")
        self.assertEqual(payload["profile"]["name"], "smoke")
        self.assertEqual(payload["artifacts"]["dataset_profile"], "public")
        self.assertEqual(payload["artifacts"]["scorer_profile"], "anchor-first")
        self.assertEqual(payload["profile"]["config"]["displacement_window"], 12)
        self.assertEqual(payload["profile"]["config"]["route_followup_limit"], 2)
        self.assertIn("--displacement-window", payload["command"])
        self.assertIn("--route-followup-limit", payload["command"])

    def test_cpu_plan_only_honors_displacement_overrides(self) -> None:
        completed = subprocess.run(
            [
                PYTHON,
                "-m",
                "kryptos.benchmark_cli",
                "--runner",
                "cpu-strategy",
                "--profile",
                "smoke",
                "--plan-only",
                "--json",
                "--displacement-window",
                "10",
                "--route-followup-limit",
                "4",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["profile"]["config"]["displacement_window"], 10)
        self.assertEqual(payload["profile"]["config"]["route_followup_limit"], 4)

    def test_gpu_plan_only_honors_layer_overrides(self) -> None:
        completed = subprocess.run(
            [
                PYTHON,
                "-m",
                "kryptos.benchmark_cli",
                "--runner",
                "gpu-opencl",
                "--profile",
                "smoke",
                "--plan-only",
                "--json",
                "--score-threshold",
                "1700",
                "--top-candidate-limit",
                "3",
                "--hydrate-limit",
                "7",
                "--min-anchor-hits",
                "4",
                "--max-post-key-length",
                "5",
                "--local-size",
                "64",
                "--focus-budget",
                "9",
                "--focus-seed-limit",
                "3",
                "--focus-neighbor-span",
                "2",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["profile"]["config"]["score_threshold"], 1700)
        self.assertEqual(payload["profile"]["config"]["top_candidate_limit"], 3)
        self.assertEqual(payload["profile"]["config"]["hydrate_limit"], 7)
        self.assertEqual(payload["profile"]["config"]["min_anchor_hits"], 4)
        self.assertEqual(payload["profile"]["config"]["max_post_key_length"], 5)
        self.assertEqual(payload["profile"]["config"]["local_size"], 64)
        self.assertEqual(payload["profile"]["config"]["focus_budget"], 9)
        self.assertEqual(payload["profile"]["config"]["focus_seed_limit"], 3)
        self.assertEqual(payload["profile"]["config"]["focus_neighbor_span"], 2)
        self.assertIn("--score-threshold", payload["command"])
        self.assertIn("--top-candidates", payload["command"])
        self.assertIn("--hydrate-limit", payload["command"])
        self.assertIn("--min-anchor-hits", payload["command"])
        self.assertIn("--local-size", payload["command"])
        self.assertIn("--focus-budget", payload["command"])
        self.assertIn("--focus-seed-limit", payload["command"])
        self.assertIn("--focus-neighbor-span", payload["command"])

    def test_benchmark_comparison_schema(self) -> None:
        baseline = {
            "runner": "cpu-strategy",
            "profile": {"name": "smoke"},
            "execution": {"attempts_per_second": 10.0},
            "artifacts": {
                "top_candidates": [
                    {
                        "total_score": 200,
                        "matched_clues": ["EASTNORTHEAST"],
                        "transform_chain": ["periodic_transposition:w7:row->column"],
                        "preview": "BASELINE",
                    }
                ]
            },
        }
        current = {
            "runner": "cpu-strategy",
            "profile": {"name": "smoke"},
            "execution": {"attempts_per_second": 11.0},
            "artifacts": {
                "top_candidates": [
                    {
                        "total_score": 260,
                        "matched_clues": ["EASTNORTHEAST", "BERLINCLOCK"],
                        "transform_chain": ["periodic_transposition:w7:row->column", "displacement:delta=-5"],
                        "preview": "CURRENT",
                    }
                ]
            },
        }
        baseline_path = REPO_ROOT / "tests" / "_benchmark_baseline.json"
        current_path = REPO_ROOT / "tests" / "_benchmark_current.json"
        try:
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
            current_path.write_text(json.dumps(current), encoding="utf-8")
            payload = build_benchmark_comparison(
                [{"label": "cpu-smoke", "baseline": str(baseline_path), "current": str(current_path)}]
            )
        finally:
            baseline_path.unlink(missing_ok=True)
            current_path.unlink(missing_ok=True)
        comparison = payload["comparisons"][0]
        self.assertEqual(comparison["label"], "cpu-smoke")
        self.assertEqual(comparison["deltas"]["top_score"], 60)
        self.assertEqual(comparison["deltas"]["matched_clue_count"], 1)
        self.assertEqual(comparison["deltas"]["attempts_per_second"], 1.0)
        self.assertTrue(comparison["improved"])
        self.assertTrue(comparison["quality_improved"])
        self.assertTrue(comparison["throughput_improved"])


if __name__ == "__main__":
    unittest.main()
