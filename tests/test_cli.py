from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


class ToolkitCliTests(unittest.TestCase):
    def test_list_strategies(self) -> None:
        completed = subprocess.run(
            [PYTHON, str(REPO_ROOT / "kryptos_toolkit.py"), "--list-strategies"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("[1] Quagmire III Running Keys", completed.stdout)
        self.assertIn("[13] Hybrid Pipeline Search", completed.stdout)
        self.assertIn("[14] Displacement Route Search", completed.stdout)
        self.assertIn("[32] Unknown-Source Running Key Sweep", completed.stdout)
        self.assertIn("[37] Transposition + Unknown-Source Running Key", completed.stdout)

    def test_flagged_strategy_returns_json(self) -> None:
        completed = subprocess.run(
            [
                PYTHON,
                str(REPO_ROOT / "kryptos_toolkit.py"),
                "--strategy",
                "11",
                "--dataset-profile",
                "public",
                "--scorer-profile",
                "geo-route",
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["strategy_selection"], "11")
        self.assertEqual(payload["dataset_profile"], "public")
        self.assertEqual(payload["scorer_profile"], "geo-route")
        self.assertEqual(payload["results"][0]["strategy_id"], "11")
        candidate = payload["results"][0]["artifacts"]["top_candidates"][0]
        self.assertEqual(
            sorted(candidate),
            ["breakdown", "corpus_id", "key_material", "matched_clues", "plaintext", "preview", "rank", "total_score", "transform_chain"],
        )

    def test_wrapped_strategies_33_to_36_run_via_toolkit(self) -> None:
        for strategy_id in ("33", "34", "35", "36"):
            completed = subprocess.run(
                [
                    PYTHON,
                    str(REPO_ROOT / "kryptos_toolkit.py"),
                    "--strategy",
                    strategy_id,
                    "--json",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["strategy_selection"], strategy_id)
            self.assertEqual(payload["results"][0]["strategy_id"], strategy_id)
            self.assertIn("raw_report", payload["results"][0]["artifacts"])

    def test_dictionary_generator_writes_requested_path(self) -> None:
        output_path = REPO_ROOT / "generated_dictionary_test.txt"
        try:
            subprocess.run(
                [
                    PYTHON,
                    str(REPO_ROOT / "generate_k4_dictionary.py"),
                    "--skip-download",
                    "--output",
                    str(output_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue(output_path.exists())
            self.assertIn("KRYPTOS", output_path.read_text(encoding="utf-8"))
        finally:
            output_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
