from __future__ import annotations

import contextlib
import io
import json
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock
from zipfile import ZipFile

from kryptos.colab import build_colab_config, build_local_snapshot_archive, build_notebook, main, parse_args


TEMP_ROOT = Path.cwd() / ".test_tmp_colab"


class ColabIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        shutil.rmtree(TEMP_ROOT, ignore_errors=True)
        TEMP_ROOT.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(TEMP_ROOT, ignore_errors=True)
    @contextlib.contextmanager
    def tempdir(self):
        path = TEMP_ROOT / uuid.uuid4().hex
        path.mkdir(parents=True, exist_ok=True)
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)

    def write_baseline_fixture(self, directory: Path) -> Path:
        payload = {
            "execution": {
                "attempts": 123456,
                "elapsed_seconds": 12.5,
                "attempts_per_second": 9876.5,
                "pass_summaries": [
                    {
                        "qualified_candidate_count": 9,
                        "hydrated_candidate_count": 4,
                        "top_candidates": [
                            {
                                "keyword": "TESTING",
                                "period": 7,
                                "raw_displacement_hint": 180,
                                "raw_best_displacement": -9,
                            }
                        ],
                    }
                ],
            },
            "artifacts": {
                "qualified_candidate_count": 9,
                "hydrated_candidate_count": 4,
            },
        }
        path = directory / "baseline.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_build_colab_config_includes_commands_baseline_and_snapshot(self) -> None:
        with self.tempdir() as tmp_path:
            baseline_path = self.write_baseline_fixture(tmp_path)
            snapshot_path = tmp_path / "snapshot.zip"
            args = parse_args(
                [
                    "--local-baseline",
                    str(baseline_path),
                    "--local-snapshot-output",
                    str(snapshot_path),
                    "--include-drive-mount",
                    "--sweeps-per-pass",
                    "25",
                ]
            )
            config = build_colab_config(args)

        self.assertEqual(config["title"], "Kryptos Colab AI Workbench")
        self.assertEqual(
            config["heavy_command"][:6],
            ["-m", "kryptos.benchmark_cli", "--runner", "gpu-opencl", "--profile", "default"],
        )
        self.assertIn("--sweeps-per-pass", config["heavy_command"])
        self.assertEqual(config["bootstrap_command"][:4], ["-m", "pip", "install", "--upgrade"])
        self.assertEqual(config["gpu_install_command"], ["-m", "pip", "install", "numpy", "pyopencl"])
        self.assertEqual(config["local_baseline_summary"]["attempts"], 123456)
        self.assertEqual(config["local_baseline_summary"]["displacement_examples"][0]["best_displacement"], -9)
        self.assertEqual(config["local_snapshot_name"], "snapshot.zip")
        self.assertTrue(config["include_drive_mount"])

    def test_build_local_snapshot_archive_uses_posix_paths(self) -> None:
        with self.tempdir() as root:
            (root / "kryptos").mkdir()
            (root / "kryptos" / "__init__.py").write_text("__all__ = []\n", encoding="utf-8")
            (root / "kryptos" / "common.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "notes.md").write_text("notes\n", encoding="utf-8")
            (root / "runs").mkdir()
            (root / "runs" / "skip.txt").write_text("skip\n", encoding="utf-8")
            output_path = root / "snapshot.zip"

            with mock.patch("kryptos.colab.REPO_ROOT", root):
                snapshot = build_local_snapshot_archive(output_path)

            self.assertEqual(snapshot, output_path)
            with ZipFile(snapshot) as archive:
                names = sorted(archive.namelist())

        self.assertIn("docs/notes.md", names)
        self.assertIn("kryptos/__init__.py", names)
        self.assertIn("kryptos/common.py", names)
        self.assertNotIn("runs/skip.txt", names)
        self.assertNotIn("snapshot.zip", names)
        self.assertFalse(any("\\" in name for name in names))

    def test_build_notebook_contains_snapshot_flow_and_resilient_helpers(self) -> None:
        args = parse_args(["--local-baseline", "missing.json", "--local-snapshot-output", "snapshot.zip"])
        config = build_colab_config(args)
        notebook = build_notebook(config)
        joined = "\n".join("".join(cell["source"]) for cell in notebook["cells"])

        self.assertEqual(notebook["nbformat"], 4)
        self.assertIn("Optional: upload a local repo snapshot zip when GitHub is behind", joined)
        self.assertIn("LOCAL_SNAPSHOT_NAME", joined)
        self.assertIn("files.upload()", joined)
        self.assertIn("resolve_workdir", joined)
        self.assertIn('os.chdir("/content")', joined)
        self.assertIn("Snapshot extracted, but the kryptos package directory is missing", joined)
        self.assertIn("run_logged(command, cwd=workdir)", joined)
        self.assertIn("from google.colab import ai", joined)
        code_titles = [cell["source"][0] for cell in notebook["cells"] if cell["cell_type"] == "code" and cell["source"]]
        self.assertTrue(all(not title.startswith("                #") for title in code_titles))

    def test_main_writes_notebook_config_and_snapshot_artifacts(self) -> None:
        with self.tempdir() as tmp_path:
            baseline_path = self.write_baseline_fixture(tmp_path)
            notebook_path = tmp_path / "workbench.ipynb"
            config_path = tmp_path / "workbench.json"
            snapshot_path = tmp_path / "snapshot.zip"
            fake_repo = tmp_path / "repo"
            (fake_repo / "kryptos").mkdir(parents=True)
            (fake_repo / "kryptos" / "__init__.py").write_text("__all__ = []\n", encoding="utf-8")
            (fake_repo / "README.md").write_text("repo\n", encoding="utf-8")

            stdout = io.StringIO()
            with mock.patch("kryptos.colab.REPO_ROOT", fake_repo), contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "--repo-url",
                        "https://example.com/kryptos.git",
                        "--repo-ref",
                        "colab-test",
                        "--local-baseline",
                        str(baseline_path),
                        "--local-snapshot-output",
                        str(snapshot_path),
                        "--notebook-output",
                        str(notebook_path),
                        "--config-output",
                        str(config_path),
                        "--json",
                    ]
                )

            payload = json.loads(stdout.getvalue())
            notebook = json.loads(notebook_path.read_text(encoding="utf-8"))
            config = json.loads(config_path.read_text(encoding="utf-8"))
            notebook_exists = notebook_path.exists()
            config_exists = config_path.exists()
            snapshot_exists = snapshot_path.exists()

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["config"]["repo_url"], "https://example.com/kryptos.git")
        self.assertEqual(config["repo_ref"], "colab-test")
        self.assertEqual(config["local_snapshot_name"], "snapshot.zip")
        self.assertGreater(config["local_snapshot_size_bytes"], 0)
        self.assertEqual(notebook["metadata"]["colab"]["name"], "kryptos_colab_ai_workbench.ipynb")
        self.assertTrue(notebook_exists)
        self.assertTrue(config_exists)
        self.assertTrue(snapshot_exists)


if __name__ == "__main__":
    unittest.main()