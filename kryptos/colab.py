from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from textwrap import dedent
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from .dashboard import write_json
from .paths import REPO_ROOT, ensure_parent

DEFAULT_REPO_URL = "https://github.com/claudlos/Kryptos.git"
DEFAULT_REPO_REF = "main"
DEFAULT_NOTEBOOK_PATH = REPO_ROOT / "notebooks" / "kryptos_colab_ai_workbench.ipynb"
DEFAULT_CONFIG_PATH = REPO_ROOT / "runs" / "colab_workbench_config.json"
DEFAULT_SMOKE_OUTPUT = "runs/colab_gpu_smoke.json"
DEFAULT_HEAVY_OUTPUT = "runs/colab_gpu_default_50sweeps.json"
DEFAULT_CPU_FALLBACK_OUTPUT = "runs/colab_cpu_default.json"
DEFAULT_AI_MODEL = "google/gemini-2.0-flash"
DEFAULT_LOCAL_BASELINE = REPO_ROOT / "runs" / "gpu_50sweep_default_baseline.json"
DEFAULT_LOCAL_SNAPSHOT = REPO_ROOT / "runs" / "colab_repo_snapshot_posix.zip"


def _run_git_command(*args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    value = completed.stdout.strip()
    return value or None


def detect_repo_url() -> str:
    return _run_git_command("remote", "get-url", "origin") or DEFAULT_REPO_URL


def detect_repo_ref() -> str:
    return _run_git_command("rev-parse", "--abbrev-ref", "HEAD") or DEFAULT_REPO_REF


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Google Colab AI notebook and config for Kryptos benchmarking."
    )
    parser.add_argument("--repo-url", help="Git URL that Colab should clone.")
    parser.add_argument("--repo-ref", help="Git ref or branch that Colab should check out.")
    parser.add_argument(
        "--runner",
        choices=["gpu-opencl", "cpu-strategy"],
        default="gpu-opencl",
        help="Primary benchmark runner for the heavier Colab pass.",
    )
    parser.add_argument("--profile", default="default", help="Benchmark profile for the heavier Colab pass.")
    parser.add_argument(
        "--smoke-profile",
        default="smoke",
        help="Smoke profile to validate the Colab runtime before the heavier pass.",
    )
    parser.add_argument(
        "--sweeps-per-pass",
        type=int,
        default=50,
        help="GPU override for the heavier Colab run. Ignored for CPU runs.",
    )
    parser.add_argument(
        "--dataset-profile",
        default="full-public",
        help="CPU override for the heavier Colab run.",
    )
    parser.add_argument(
        "--scorer-profile",
        default="anchor-first",
        help="CPU override for the heavier Colab run.",
    )
    parser.add_argument(
        "--smoke-output",
        default=DEFAULT_SMOKE_OUTPUT,
        help="Artifact path for the smoke benchmark inside Colab.",
    )
    parser.add_argument(
        "--heavy-output",
        default=DEFAULT_HEAVY_OUTPUT,
        help="Artifact path for the heavier benchmark inside Colab.",
    )
    parser.add_argument(
        "--cpu-fallback-output",
        default=DEFAULT_CPU_FALLBACK_OUTPUT,
        help="Artifact path for the CPU fallback benchmark inside Colab.",
    )
    parser.add_argument("--ai-model", default=DEFAULT_AI_MODEL, help="Model name passed to google.colab.ai.")
    parser.add_argument(
        "--local-baseline",
        default=str(DEFAULT_LOCAL_BASELINE),
        help="Local GPU benchmark artifact to summarize in the notebook header.",
    )
    parser.add_argument(
        "--local-snapshot-output",
        default=str(DEFAULT_LOCAL_SNAPSHOT),
        help="Local zip artifact that packages the current working tree for Colab upload.",
    )
    parser.add_argument(
        "--notebook-output",
        default=str(DEFAULT_NOTEBOOK_PATH),
        help="Notebook output path.",
    )
    parser.add_argument(
        "--config-output",
        default=str(DEFAULT_CONFIG_PATH),
        help="JSON config output path.",
    )
    parser.add_argument(
        "--include-drive-mount",
        action="store_true",
        help="Include a Drive export cell in the generated notebook.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the generated config JSON to stdout.")
    return parser.parse_args(argv)


def load_benchmark_payload(path: str | Path) -> dict[str, Any] | None:
    candidate = Path(path)
    if not candidate.exists():
        return None
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _display_path(value: str | Path) -> str:
    candidate = Path(value)
    try:
        return candidate.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(candidate)


def summarize_local_baseline(
    payload: dict[str, Any] | None,
    artifact_path: str | Path,
) -> dict[str, Any] | None:
    if not payload:
        return None
    execution = payload.get("execution", {})
    pass_summaries = execution.get("pass_summaries") or []
    pass_summary = pass_summaries[0] if pass_summaries else {}
    artifacts = payload.get("artifacts", {})
    top_candidates = pass_summary.get("top_candidates") or artifacts.get("top_candidates") or []
    displacement_examples: list[dict[str, Any]] = []
    for candidate in top_candidates:
        displacement_hint = int(candidate.get("raw_displacement_hint", 0))
        if displacement_hint <= 0:
            continue
        displacement_examples.append(
            {
                "keyword": candidate.get("keyword"),
                "period": candidate.get("period"),
                "displacement_hint": displacement_hint,
                "best_displacement": int(candidate.get("raw_best_displacement", 0)),
            }
        )
        if len(displacement_examples) >= 3:
            break
    return {
        "artifact_path": _display_path(artifact_path),
        "attempts": int(execution.get("attempts", 0)),
        "elapsed_seconds": round(float(execution.get("elapsed_seconds", 0.0)), 6),
        "attempts_per_second": round(float(execution.get("attempts_per_second", 0.0)), 6),
        "qualified_candidate_count": int(
            artifacts.get("qualified_candidate_count", pass_summary.get("qualified_candidate_count", 0))
        ),
        "hydrated_candidate_count": int(
            artifacts.get("hydrated_candidate_count", pass_summary.get("hydrated_candidate_count", 0))
        ),
        "displacement_examples": displacement_examples,
    }


def build_benchmark_command(
    *,
    runner: str,
    profile: str,
    output_path: str,
    sweeps_per_pass: int | None = None,
    dataset_profile: str | None = None,
    scorer_profile: str | None = None,
) -> list[str]:
    command = [
        "-m",
        "kryptos.benchmark_cli",
        "--runner",
        runner,
        "--profile",
        profile,
        "--json",
        "--output",
        output_path,
    ]
    if runner == "gpu-opencl" and sweeps_per_pass is not None:
        command.extend(["--sweeps-per-pass", str(sweeps_per_pass)])
    if runner == "cpu-strategy":
        if dataset_profile is not None:
            command.extend(["--dataset-profile", dataset_profile])
        if scorer_profile is not None:
            command.extend(["--scorer-profile", scorer_profile])
    return command


def build_local_snapshot_archive(destination: str | Path) -> Path:
    output_path = ensure_parent(destination)
    if output_path.exists():
        output_path.unlink()
    output_resolved = output_path.resolve()
    exclude_parts = {
        ".git",
        ".venv",
        "runs",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".codex-dist",
        ".codex-tmp",
        ".test_tmp_colab",
    }
    with ZipFile(output_path, "w", ZIP_DEFLATED) as archive:
        for file_path in REPO_ROOT.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.resolve() == output_resolved:
                continue
            relative = file_path.relative_to(REPO_ROOT)
            if any(part in exclude_parts for part in relative.parts):
                continue
            archive.write(file_path, relative.as_posix())
    return output_path


def build_colab_config(args: argparse.Namespace) -> dict[str, Any]:
    repo_url = args.repo_url or detect_repo_url()
    repo_ref = args.repo_ref or detect_repo_ref()
    baseline_payload = load_benchmark_payload(args.local_baseline)
    baseline_summary = summarize_local_baseline(baseline_payload, args.local_baseline)
    smoke_command = build_benchmark_command(
        runner="gpu-opencl",
        profile=args.smoke_profile,
        output_path=args.smoke_output,
        sweeps_per_pass=1,
    )
    heavy_command = build_benchmark_command(
        runner=args.runner,
        profile=args.profile,
        output_path=args.heavy_output,
        sweeps_per_pass=args.sweeps_per_pass if args.runner == "gpu-opencl" else None,
        dataset_profile=args.dataset_profile,
        scorer_profile=args.scorer_profile,
    )
    cpu_fallback_command = build_benchmark_command(
        runner="cpu-strategy",
        profile="default",
        output_path=args.cpu_fallback_output,
        dataset_profile=args.dataset_profile,
        scorer_profile=args.scorer_profile,
    )
    bootstrap_command = [
        "-m",
        "pip",
        "install",
        "--upgrade",
        "pip",
        "setuptools>=69",
        "wheel",
    ]
    gpu_install_command = [
        "-m",
        "pip",
        "install",
        "numpy",
        "pyopencl",
    ]
    return {
        "title": "Kryptos Colab AI Workbench",
        "repo_url": repo_url,
        "repo_ref": repo_ref,
        "workdir": "/content/Kryptos",
        "bootstrap_command": bootstrap_command,
        "gpu_install_command": gpu_install_command,
        "smoke_command": smoke_command,
        "heavy_command": heavy_command,
        "cpu_fallback_command": cpu_fallback_command,
        "smoke_output": args.smoke_output,
        "heavy_output": args.heavy_output,
        "cpu_fallback_output": args.cpu_fallback_output,
        "ai_model": args.ai_model,
        "local_snapshot_name": Path(args.local_snapshot_output).name,
        "local_snapshot_path": _display_path(args.local_snapshot_output),
        "primary_runner": args.runner,
        "primary_profile": args.profile,
        "include_drive_mount": bool(args.include_drive_mount),
        "local_baseline_summary": baseline_summary,
        "source_notebook": (
            "https://colab.research.google.com/github/googlecolab/colabtools/blob/main/notebooks/"
            "Getting_started_with_google_colab_ai.ipynb"
        ),
        "source_release_notes": "https://colab.google/release-notes/",
    }


def _lines(text: str) -> list[str]:
    return [line + "\n" for line in text.strip("\n").splitlines()]


def markdown_cell(text: str) -> dict[str, Any]:
    normalized = "\n".join(line.removeprefix("                ") for line in text.splitlines())
    return {"cell_type": "markdown", "metadata": {}, "source": _lines(normalized)}


def code_cell(text: str) -> dict[str, Any]:
    return {
        "cell_type": "code",
        "metadata": {},
        "execution_count": None,
        "outputs": [],
        "source": _lines(text),
    }


def render_baseline_markdown(config: dict[str, Any]) -> str:
    summary = config.get("local_baseline_summary")
    if not summary:
        return "No local GPU baseline artifact was available when this notebook was generated."
    lines = [
        f"Local reference baseline from `{Path(summary['artifact_path']).name}`:",
        f"- Attempts: `{summary['attempts']}`",
        f"- Elapsed seconds: `{summary['elapsed_seconds']}`",
        f"- Attempts/second: `{summary['attempts_per_second']}`",
        f"- Qualified candidates: `{summary['qualified_candidate_count']}`",
        f"- Hydrated candidates: `{summary['hydrated_candidate_count']}`",
    ]
    examples = summary.get("displacement_examples") or []
    if examples:
        lines.append("- Notable displacement-bearing survivors:")
        for example in examples:
            lines.append(
                f"  - `{example['keyword']}` / period `{example['period']}` / hint `{example['displacement_hint']}` / delta `{example['best_displacement']}`"
            )
    return "\n".join(lines)


def build_notebook(config: dict[str, Any]) -> dict[str, Any]:
    baseline_markdown = render_baseline_markdown(config)
    snapshot_name = config["local_snapshot_name"]
    cells: list[dict[str, Any]] = [
        markdown_cell(
            dedent(
                f"""
                # Kryptos Colab AI Workbench

                This notebook is generated from the Kryptos repo so Colab can do two jobs in one place:

                - run Kryptos benchmark passes on a disposable Colab runtime
                - use the `google.colab.ai` workflow from Google's public preview notebook to summarize retained candidates and propose next pruning moves

                Primary source notebook: [{config['source_notebook']}]({config['source_notebook']})

                {baseline_markdown}

                Local snapshot workflow:

                - the generator also creates a local snapshot archive named `{snapshot_name}`
                - if GitHub is behind your working tree, upload that archive with the snapshot cell before running the GPU benchmarks

                Notes:

                - the current repo GPU path is OpenCL-based, so this notebook probes OpenCL explicitly before launching the heavier run
                - if the Colab runtime does not expose a working OpenCL platform, use the CPU fallback cell instead of forcing the GPU runner
                - keep this work aligned to public, reproducible K4 method reconstruction only
                """
            )
        ),
        code_cell(
            dedent(
                f"""
                # @title Configure the workbench
                REPO_URL = {config['repo_url']!r}
                REPO_REF = {config['repo_ref']!r}
                WORKDIR = {config['workdir']!r}
                BOOTSTRAP_COMMAND = {config['bootstrap_command']!r}
                GPU_INSTALL_COMMAND = {config['gpu_install_command']!r}

                SMOKE_COMMAND = {config['smoke_command']!r}
                HEAVY_COMMAND = {config['heavy_command']!r}
                CPU_FALLBACK_COMMAND = {config['cpu_fallback_command']!r}

                SMOKE_OUTPUT = {config['smoke_output']!r}
                HEAVY_OUTPUT = {config['heavy_output']!r}
                CPU_FALLBACK_OUTPUT = {config['cpu_fallback_output']!r}
                AI_MODEL_NAME = {config['ai_model']!r}
                LOCAL_SNAPSHOT_NAME = {config['local_snapshot_name']!r}
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Helper: run commands and show stdout/stderr on failure
                import os
                import pathlib
                import subprocess

                def ensure_content_cwd():
                    os.chdir("/content")

                def resolve_workdir():
                    workdir = pathlib.Path(WORKDIR)
                    return workdir if workdir.is_absolute() else pathlib.Path("/content") / workdir

                def resolve_artifact(path_value):
                    candidate = pathlib.Path(path_value)
                    return candidate if candidate.is_absolute() else resolve_workdir() / candidate

                def run_logged(command, *, cwd=None):
                    workdir = pathlib.Path(cwd) if cwd is not None else resolve_workdir()
                    if not workdir.exists():
                        workdir = pathlib.Path("/content")
                        workdir.mkdir(parents=True, exist_ok=True)
                    env = os.environ.copy()
                    env["PYTHONPATH"] = str(workdir) if not env.get("PYTHONPATH") else f"{workdir}:{env['PYTHONPATH']}"
                    completed = subprocess.run(
                        command,
                        cwd=workdir,
                        env=env,
                        text=True,
                        capture_output=True,
                    )
                    if completed.stdout:
                        print(completed.stdout)
                    if completed.stderr:
                        print(completed.stderr)
                    completed.check_returncode()
                    return completed
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Clone the repo and prepare the Python environment
                import shutil
                import sys

                for dependency in ("os", "pathlib", "subprocess"):
                    if dependency not in globals():
                        raise RuntimeError("Run the helper cell before bootstrapping the repo.")

                ensure_content_cwd()
                workdir = resolve_workdir()
                if workdir.exists():
                    shutil.rmtree(workdir)
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--branch", REPO_REF, REPO_URL, str(workdir)],
                    check=True,
                )
                os.chdir(workdir)
                command = [sys.executable, *BOOTSTRAP_COMMAND]
                print("Launching:", " ".join(command))
                run_logged(command, cwd=workdir)
                if str(workdir) not in sys.path:
                    sys.path.insert(0, str(workdir))
                existing_pythonpath = os.environ.get("PYTHONPATH", "")
                os.environ["PYTHONPATH"] = (
                    str(workdir) if not existing_pythonpath else f"{workdir}:{existing_pythonpath}"
                )
                print(f"Bootstrapped {workdir} and exported it to PYTHONPATH")
                if not (workdir / "kryptos").exists():
                    print("The cloned checkout does not contain the local kryptos package changes.")
                    print(f"Upload {LOCAL_SNAPSHOT_NAME} with the snapshot cell below if GitHub is behind your local working tree.")
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Optional: upload a local repo snapshot zip when GitHub is behind
                from google.colab import files
                import os
                import shutil
                import sys
                import zipfile

                ensure_content_cwd()
                print(f"Choose {LOCAL_SNAPSHOT_NAME} from your local machine if you need your current unpushed code.")
                uploaded = files.upload()
                if not uploaded:
                    raise RuntimeError("No snapshot archive was uploaded.")

                archive_name, archive_bytes = next(iter(uploaded.items()))
                archive_path = pathlib.Path("/content") / archive_name
                archive_path.write_bytes(archive_bytes)

                workdir = resolve_workdir()
                if workdir.exists():
                    shutil.rmtree(workdir)
                workdir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(archive_path) as zf:
                    zf.extractall(workdir)

                if not (workdir / "kryptos").exists():
                    raise RuntimeError(
                        "Snapshot extracted, but the kryptos package directory is missing. "
                        "Regenerate the archive with POSIX-style zip paths and retry."
                    )

                os.chdir(workdir)
                if str(workdir) not in sys.path:
                    sys.path.insert(0, str(workdir))
                existing_pythonpath = os.environ.get("PYTHONPATH", "")
                os.environ["PYTHONPATH"] = (
                    str(workdir) if not existing_pythonpath else f"{workdir}:{existing_pythonpath}"
                )
                print(f"Extracted snapshot to {workdir} and exported it to PYTHONPATH")
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Install OpenCL diagnostics (safe to rerun)
                import subprocess

                ensure_content_cwd()
                subprocess.run(["apt-get", "update"], check=True)
                subprocess.run(["apt-get", "install", "-y", "clinfo", "ocl-icd-opencl-dev", "opencl-headers"], check=True)
                subprocess.run(["bash", "-lc", "clinfo | head -n 120"], check=False)
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Install GPU Python packages after OpenCL headers
                import pathlib
                import sys

                ensure_content_cwd()
                command = [sys.executable, *GPU_INSTALL_COMMAND]
                print("Launching:", " ".join(command))
                run_logged(command, cwd=pathlib.Path("/content"))
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Probe OpenCL availability
                import json
                import pyopencl as cl

                platform_summaries = []
                for platform in cl.get_platforms():
                    platform_summaries.append(
                        {
                            "name": platform.name,
                            "vendor": platform.vendor,
                            "version": platform.version,
                            "devices": [device.name for device in platform.get_devices()],
                        }
                    )
                print(json.dumps(platform_summaries, indent=2))
                if not platform_summaries:
                    raise RuntimeError("No OpenCL platforms detected. Use the CPU fallback command in this notebook instead.")
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Run a smoke benchmark first
                import sys

                ensure_content_cwd()
                workdir = resolve_workdir()
                if not workdir.exists():
                    raise FileNotFoundError(f"{workdir} is missing. Run the clone or snapshot upload cell first.")
                command = [sys.executable, *SMOKE_COMMAND]
                print("Launching:", " ".join(command))
                run_logged(command, cwd=workdir)
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Run the heavier benchmark
                import sys
                import time

                ensure_content_cwd()
                workdir = resolve_workdir()
                if not workdir.exists():
                    raise FileNotFoundError(f"{workdir} is missing. Run the clone or snapshot upload cell first.")
                started = time.time()
                command = [sys.executable, *HEAVY_COMMAND]
                print("Launching:", " ".join(command))
                run_logged(command, cwd=workdir)
                print(f"Completed in {time.time() - started:.2f}s")
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title CPU fallback if OpenCL is unavailable
                import sys
                import time

                ensure_content_cwd()
                workdir = resolve_workdir()
                if not workdir.exists():
                    raise FileNotFoundError(f"{workdir} is missing. Run the clone or snapshot upload cell first.")
                started = time.time()
                command = [sys.executable, *CPU_FALLBACK_COMMAND]
                print("Launching:", " ".join(command))
                run_logged(command, cwd=workdir)
                print(f"Completed in {time.time() - started:.2f}s")
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Inspect retained candidates
                import json

                artifact_path = resolve_artifact(HEAVY_OUTPUT)
                if not artifact_path.exists():
                    artifact_path = resolve_artifact(CPU_FALLBACK_OUTPUT)
                payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                top_candidates = payload.get("artifacts", {}).get("top_candidates", [])[:10]
                for index, candidate in enumerate(top_candidates, start=1):
                    summary = {
                        "rank": index,
                        "keyword": candidate.get("keyword"),
                        "period": candidate.get("period"),
                        "best_mode": candidate.get("best_mode"),
                        "best_score": candidate.get("best_score"),
                        "raw_displacement_hint": candidate.get("raw_displacement_hint"),
                        "raw_best_displacement": candidate.get("raw_best_displacement"),
                        "preview": candidate.get("best_preview"),
                    }
                    print(json.dumps(summary, indent=2))
                """
            )
        ),
        code_cell(
            dedent(
                """
                # @title Summarize the retained candidates with Colab AI
                from google.colab import ai
                import json

                artifact_path = resolve_artifact(HEAVY_OUTPUT)
                if not artifact_path.exists():
                    artifact_path = resolve_artifact(CPU_FALLBACK_OUTPUT)
                payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                top_candidates = payload.get("artifacts", {}).get("top_candidates", [])[:10]
                candidate_json = json.dumps(top_candidates, indent=2)
                prompt = (
                    "You are analyzing Kryptos K4 benchmark output.\\n\\n"
                    "Constraints:\\n"
                    "- work only from public, reproducible evidence\\n"
                    "- do not invent private plaintext, leaked keys, or auction-only material\\n"
                    "- optimize for the next concrete pruning or search move\\n\\n"
                    "Tasks:\\n"
                    "1. Summarize the strongest repeated structural signals across the retained candidates.\\n"
                    "2. Call out any displacement clusters or periodic/transposition fingerprints worth exploiting on GPU.\\n"
                    "3. Recommend the next benchmark override to try and why.\\n\\n"
                    "Candidate JSON:\\n"
                    f"{candidate_json}\\n"
                )
                response = ai.generate_text(prompt, model_name=AI_MODEL_NAME)
                print(response)
                """
            )
        ),
    ]
    if config["include_drive_mount"]:
        cells.append(
            code_cell(
                dedent(
                    """
                    # Optional: export artifacts to Google Drive
                    from google.colab import drive
                    import shutil

                    drive.mount('/content/drive')
                    export_dir = pathlib.Path('/content/drive/MyDrive/Kryptos_runs')
                    export_dir.mkdir(parents=True, exist_ok=True)
                    for artifact in [SMOKE_OUTPUT, HEAVY_OUTPUT, CPU_FALLBACK_OUTPUT]:
                        source = resolve_artifact(artifact)
                        if source.exists():
                            shutil.copy2(source, export_dir / source.name)
                    print(f"Copied artifacts to {export_dir}")
                    """
                )
            )
        )
    return {
        "cells": cells,
        "metadata": {
            "colab": {
                "name": "kryptos_colab_ai_workbench.ipynb",
                "provenance": [],
            },
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def write_notebook(path: str | Path, notebook: dict[str, Any]) -> Path:
    destination = ensure_parent(path)
    destination.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")
    return destination


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    snapshot_path = build_local_snapshot_archive(args.local_snapshot_output)
    config = build_colab_config(args)
    config["local_snapshot_name"] = snapshot_path.name
    config["local_snapshot_path"] = _display_path(snapshot_path)
    config["local_snapshot_size_bytes"] = snapshot_path.stat().st_size
    notebook = build_notebook(config)
    notebook_path = write_notebook(args.notebook_output, notebook)
    config_path = write_json(args.config_output, config)
    if args.json:
        payload = {
            "notebook_path": str(notebook_path),
            "config_path": str(config_path),
            "config": config,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Wrote notebook to {notebook_path}")
        print(f"Wrote config to {config_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())