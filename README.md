# Kryptos K4 Research Toolkit

A Python-first research repo for experimenting with possible solutions to the unsolved K4 section of Jim Sanborn's Kryptos sculpture.

## Overview

Live dashboard: [https://claudlos.github.io/Kryptos/](https://claudlos.github.io/Kryptos/)

The repository now exposes its research state through structured CLI results and a static dashboard backed by generated JSON instead of hand-maintained copy.

## Repository Layout

- `kryptos_toolkit.py`: primary CLI for running the Python strategies and exporting structured JSON.
- `k4_analyzer.py`: clue-position and Vigenere-shift analysis for the known anchors.
- `generate_k4_dictionary.py`: builds the dictionary used by the CPU and GPU fractionation runs.
- `gpu_opencl_suite.py`: OpenCL Bifid sweep with explicit pass accounting and finite defaults.
- `kryptos_deluxe_suite.mojo`: Mojo-based mutated sweep prototype.
- `linux_native_suite.mojo`: benchmark scaffold, not a full K4 decryptor.
- `docs/`: static dashboard site powered by `docs/data/dashboard.json`.
- `tests/`: `unittest` coverage for core invariants and CLI behavior.

## Installation

Base install:

```bash
pip install -e .
```

GPU-enabled install:

```bash
pip install -e .[gpu]
```

Legacy dependency path:

1. Install the package plus GPU extras:
   ```bash
   pip install -r requirements.txt
   ```
2. Generate the dictionary file if you need to rebuild it:
   ```bash
   python generate_k4_dictionary.py
   ```

## CLI Usage

List strategies:

```bash
python kryptos_toolkit.py --list-strategies
```

Installed console script:

```bash
kryptos-toolkit --list-strategies
```

Run one strategy and emit JSON:

```bash
python kryptos_toolkit.py --strategy 1 --json
```

Run the full Python suite, save a run artifact, and refresh the dashboard data:

```bash
python kryptos_toolkit.py --strategy all \
  --output runs/latest_run.json \
  --dashboard-output docs/data/dashboard.json
```

Generate clue analysis data:

```bash
python k4_analyzer.py --json
```

Installed console script:

```bash
kryptos-analyze --json
```

Run the GPU sweep for one pass:

```bash
python gpu_opencl_suite.py --passes 1
```

Run the GPU sweep continuously until interrupted:

```bash
python gpu_opencl_suite.py --continuous
```

Installed console script:

```bash
kryptos-gpu --profile smoke --json
```

## Benchmark Profiles

Use the unified benchmark entry point to plan or run comparable benchmark profiles:

Plan a GPU smoke benchmark:

```bash
python -m kryptos.benchmark_cli --runner gpu-opencl --profile smoke --plan-only --json
```

Plan a Mojo deluxe smoke benchmark:

```bash
python -m kryptos.benchmark_cli --runner mojo-deluxe --profile smoke --plan-only --json
```

If the console scripts are installed:

```bash
kryptos-benchmark --runner gpu-opencl --profile smoke --plan-only
```

Available runners:

- `gpu-opencl`
- `mojo-deluxe`
- `mojo-scaffold`

Available profiles per runner:

- `smoke`
- `default`
- `deep`

Generated benchmark plan artifacts in this repo:

- `runs/gpu_benchmark_plan.json`
- `runs/mojo_deluxe_benchmark_plan.json`
- `runs/mojo_scaffold_benchmark_plan.json`

## Google Colab AI Workbench

Generate the Colab notebook/config artifacts and a local snapshot zip for upload to Colab:

```bash
python -m kryptos.colab --include-drive-mount --json
```

Installed console script:

```bash
kryptos-colab --include-drive-mount --json
```

Default outputs:

- `notebooks/kryptos_colab_ai_workbench.ipynb`
- `runs/colab_workbench_config.json`
- `runs/colab_repo_snapshot_posix.zip` (local-only upload artifact; keep it out of public commits)

The generated notebook is designed around Google's `google.colab.ai` workflow and adds Kryptos-specific cells to:

- clone and install this repo in Colab
- upload and unpack the generated local snapshot zip when the local working tree is ahead of GitHub or you are testing unpushed changes
- probe OpenCL availability before running the GPU benchmark
- run a smoke pass and a heavier benchmark pass
- fall back to the `cpu-strategy` runner if OpenCL is unavailable
- summarize retained candidates with `google.colab.ai`

## Testing

```bash
python -m unittest discover -s tests -v
```

## Notes

- The Python toolkit returns structured results for each strategy, including attempts, elapsed time, previews, and clue hits.
- The dashboard in `docs/` reads its data from `docs/data/dashboard.json`, which can be regenerated directly from `kryptos_toolkit.py`.
- The historical speed figures in the site are repository benchmark notes, not guarantees for every machine.
- `linux_native_suite.mojo` is intentionally labeled as a benchmark scaffold so the docs do not overstate what it does.
- `pyproject.toml` defines installable console scripts for the toolkit, analyzer, dictionary generator, GPU runner, and benchmark orchestrator.
