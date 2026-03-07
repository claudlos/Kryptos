from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from kryptos.benchmark_cli import parse_mojo_markers
from kryptos.benchmarking import get_benchmark_profile, list_profiles, list_runners


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

    def test_gpu_default_profile_is_tuned_for_pruning(self) -> None:
        profile = get_benchmark_profile("gpu-opencl", "default")
        self.assertEqual(profile["score_threshold"], 1700)
        self.assertEqual(profile["min_anchor_hits"], 5)

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
        self.assertIn("--score-threshold", payload["command"])
        self.assertIn("--top-candidates", payload["command"])
        self.assertIn("--hydrate-limit", payload["command"])
        self.assertIn("--min-anchor-hits", payload["command"])


if __name__ == "__main__":
    unittest.main()
