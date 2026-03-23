from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from kryptos.dashboard import build_dashboard_payload
from kryptos.ledger import build_adaptive_guidance, build_experiment_plan, build_ledger_summary, merge_benchmark_into_ledger, merge_run_into_ledger
from kryptos.runtime import StrategyRuntimeConfig
from strategy10_fractionation import resolve_fractionation_search_space, resolve_fractionation_shortlist_limit
from strategy12_periodic_transposition_hillclimb import resolve_periodic_search_space
from strategy13_hybrid_pipeline_search import resolve_stage_family_order


REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def build_run_summary(
    *,
    strategy_id: str,
    strategy_name: str,
    plaintext: str,
    total_score: int,
    transform_chain: list[str],
    matched_clues: list[str],
) -> dict[str, object]:
    return {
        "strategy_selection": "all",
        "result_count": 1,
        "dataset_profile": "public",
        "scorer_profile": "anchor-first",
        "results": [
            {
                "strategy_id": strategy_id,
                "name": strategy_name,
                "objective": "Synthetic regression",
                "hypothesis": "Synthetic regression",
                "status": "candidate",
                "summary": "Synthetic regression",
                "best_preview": plaintext[:72],
                "matched_clues": matched_clues,
                "metrics": {
                    "attempts": 10,
                    "unique_attempts": 10,
                    "repeated_attempts": 0,
                    "elapsed_seconds": 0.25,
                },
                "notes": [],
                "artifacts": {
                    "top_candidates": [
                        {
                            "rank": 1,
                            "total_score": total_score,
                            "breakdown": {
                                "anchor": 600,
                                "language": 420,
                                "domain": 210,
                                "entity": 150,
                                "structure": 80,
                                "penalty": 20,
                                "total": total_score,
                            },
                            "transform_chain": transform_chain,
                            "key_material": {"seed": strategy_id},
                            "corpus_id": "official",
                            "preview": plaintext[:72],
                            "matched_clues": matched_clues,
                            "plaintext": plaintext,
                        }
                    ],
                    "best_text": plaintext,
                },
            }
        ],
    }


def build_gpu_summary(
    *,
    plaintext: str,
    best_score: int,
    transform_chain: list[str],
    matched_clues: list[str],
    keyword: str = "CLOCK",
    period: int = 7,
) -> dict[str, object]:
    return {
        "runner": "gpu-opencl",
        "profile": {"name": "smoke"},
        "execution": {"attempts": 4096},
        "artifacts": {
            "top_candidates": [
                {
                    "best_score": best_score,
                    "total_score": best_score,
                    "best_preview": plaintext[:72],
                    "preview": plaintext[:72],
                    "plaintext": plaintext,
                    "breakdown": {
                        "anchor": 620,
                        "language": 390,
                        "domain": 190,
                        "entity": 140,
                        "structure": 250,
                        "penalty": 10,
                        "total": best_score,
                    },
                    "transform_chain": transform_chain,
                    "matched_clues": matched_clues,
                    "key_material": {
                        "stage1": {"keyword": keyword, "period": period, "mutation_id": 3},
                        "stage2": {"mode": "repeating", "key": "BERLIN", "key_length": 6},
                    },
                    "raw_periodic_hint": 280,
                    "raw_displacement_hint": 180,
                    "raw_layer_hint": 140,
                    "raw_ngram_hint": 90,
                }
            ]
        },
    }


class ResearchLedgerTests(unittest.TestCase):
    def test_merge_run_into_ledger_accumulates_consensus_evidence(self) -> None:
        shared_plaintext = "X" * 21 + "EASTNORTHEAST" + "X" * 29 + "BERLINCLOCK" + "MESSAGE" + "X" * 16
        alternate_plaintext = shared_plaintext[:80] + "WORLDCLOCKMESSAGE"

        first_run = build_run_summary(
            strategy_id="10",
            strategy_name="Fractionation Pipeline",
            plaintext=shared_plaintext,
            total_score=540,
            transform_chain=["bifid:KRYPTOS:period=7", "direct", "post_vigenere:BERLIN"],
            matched_clues=["EASTNORTHEAST", "BERLINCLOCK"],
        )
        second_run = build_run_summary(
            strategy_id="13",
            strategy_name="Hybrid Pipeline Search",
            plaintext=shared_plaintext,
            total_score=560,
            transform_chain=["running_key:official:offset=0", "post_periodic_transposition:w7:row->column"],
            matched_clues=["EASTNORTHEAST", "BERLINCLOCK"],
        )
        third_run = build_run_summary(
            strategy_id="12",
            strategy_name="Periodic Transposition Hillclimb",
            plaintext=alternate_plaintext,
            total_score=490,
            transform_chain=["post_periodic_transposition:w7:row->column"],
            matched_clues=["BERLINCLOCK"],
        )

        ledger = merge_run_into_ledger(None, first_run, observed_at="2026-03-08T10:00:00+00:00")
        ledger = merge_run_into_ledger(ledger, second_run, observed_at="2026-03-08T11:00:00+00:00")
        ledger = merge_run_into_ledger(ledger, third_run, observed_at="2026-03-08T12:00:00+00:00")

        self.assertEqual(ledger["runs_merged"], 3)
        self.assertEqual(ledger["candidate_count"], 2)
        self.assertEqual(ledger["observations_merged"], 3)

        top_candidate = ledger["candidates"][0]
        self.assertEqual(top_candidate["observation_count"], 2)
        self.assertEqual(top_candidate["run_count"], 2)
        self.assertEqual(top_candidate["strategy_ids"], ["10", "13"])
        self.assertEqual(top_candidate["best_score"], 560)
        self.assertGreater(top_candidate["consensus_score"], top_candidate["best_score"])
        self.assertEqual(top_candidate["best_observation"]["strategy_id"], "13")

        summary = build_ledger_summary(ledger)
        self.assertEqual(summary["strategy_count"], 3)
        self.assertEqual(summary["top_candidates"][0]["strategy_count"], 2)
        self.assertTrue(summary["experiment_plan"]["enabled"])
        self.assertEqual(summary["experiment_plan"]["recommended_experiments"][0]["stage_family"], "periodic_transposition")

        dashboard = build_dashboard_payload(first_run, research_memory=summary)
        self.assertEqual(dashboard["research_memory"]["candidate_count"], 2)
        self.assertTrue(dashboard["research_memory"]["experiment_plan"]["enabled"])

    def test_gpu_benchmark_candidates_merge_into_ledger_and_drive_guidance(self) -> None:
        shared_plaintext = "X" * 21 + "EASTNORTHEAST" + "X" * 29 + "BERLINCLOCK" + "MESSAGE" + "X" * 16
        gpu_summary = build_gpu_summary(
            plaintext=shared_plaintext,
            best_score=575,
            transform_chain=["bifid:CLOCK:period=7", "direct", "post_periodic_transposition:w7:row->column"],
            matched_clues=["EASTNORTHEAST", "BERLINCLOCK"],
        )

        ledger = merge_benchmark_into_ledger(None, gpu_summary, observed_at="2026-03-08T13:00:00+00:00")
        candidate = ledger["candidates"][0]
        guidance = build_adaptive_guidance(ledger)
        experiment_plan = build_experiment_plan(ledger)
        config = StrategyRuntimeConfig(adaptive_guidance=guidance, width_min=5, width_max=9)

        self.assertEqual(ledger["candidate_count"], 1)
        self.assertEqual(candidate["strategy_ids"], ["gpu-opencl"])
        self.assertEqual(candidate["best_observation"]["raw_periodic_hint"], 280)
        self.assertIn("bifid", candidate["transform_families"])
        self.assertIn("post_periodic_transposition", candidate["transform_families"])

        self.assertTrue(guidance["enabled"])
        self.assertEqual(guidance["preferred_stage_families"][0], "periodic_transposition")
        self.assertEqual(guidance["preferred_keywords"][0], "CLOCK")
        self.assertEqual(guidance["preferred_periods"][0], 7)
        self.assertTrue(experiment_plan["enabled"])
        self.assertEqual(experiment_plan["recommended_experiments"][0]["stage_family"], "periodic_transposition")
        self.assertEqual(experiment_plan["recommended_experiments"][0]["target_strategies"][0]["id"], "12")
        self.assertIn("gpu-opencl", experiment_plan["recommended_experiments"][0]["coverage"]["observed_strategy_ids"])

        keywords, periods = resolve_fractionation_search_space(config)
        widths, _periodic_keywords = resolve_periodic_search_space(config, shared_plaintext)
        stage_order = resolve_stage_family_order(config)
        fractionation_shortlist = resolve_fractionation_shortlist_limit(config, 72)

        self.assertEqual(keywords[0], "CLOCK")
        self.assertEqual(periods[0], 7)
        self.assertEqual(widths[0], 7)
        self.assertEqual(stage_order[0], "periodic_transposition")
        self.assertGreater(fractionation_shortlist, max(config.candidate_limit * 4, 12))

    def test_cli_can_write_ledger_and_embed_memory_in_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            run_path = root / "run.json"
            ledger_path = root / "ledger.json"
            dashboard_path = root / "dashboard.json"
            plan_path = root / "next-experiments.json"

            subprocess.run(
                [
                    PYTHON,
                    str(REPO_ROOT / "kryptos_toolkit.py"),
                    "--strategy",
                    "11",
                    "--candidate-limit",
                    "2",
                    "--output",
                    str(run_path),
                    "--ledger-output",
                    str(ledger_path),
                    "--dashboard-output",
                    str(dashboard_path),
                    "--plan-output",
                    str(plan_path),
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )

            completed = subprocess.run(
                [
                    PYTHON,
                    str(REPO_ROOT / "kryptos_toolkit.py"),
                    "--strategy",
                    "11",
                    "--candidate-limit",
                    "2",
                    "--ledger-input",
                    str(ledger_path),
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
            )

            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
            experiment_plan = json.loads(plan_path.read_text(encoding="utf-8"))
            adaptive_run = json.loads(completed.stdout)

        self.assertEqual(ledger["runs_merged"], 1)
        self.assertTrue(ledger["top_candidates"])
        self.assertEqual(dashboard["latest_run"]["result_count"], 1)
        self.assertEqual(dashboard["research_memory"]["candidate_count"], ledger["candidate_count"])
        self.assertEqual(dashboard["research_memory"]["top_candidates"][0]["fingerprint"], ledger["top_candidates"][0]["fingerprint"])
        self.assertTrue(adaptive_run["adaptive_guidance"]["enabled"])
        self.assertTrue(experiment_plan["enabled"])
        self.assertTrue(experiment_plan["recommended_experiments"])
        self.assertEqual(dashboard["research_memory"]["experiment_plan"]["recommended_experiments"][0]["rank"], 1)
        self.assertIn("experiment_plan", adaptive_run)


if __name__ == "__main__":
    unittest.main()
