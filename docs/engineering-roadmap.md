# Engineering Roadmap

## Completed In This Pass

- Centralized shared constants, crypto helpers, path handling, result models, and dashboard export code under `kryptos/`.
- Refactored all ten Python strategies to return structured `StrategyResult` objects instead of ad hoc print-only output.
- Rebuilt `kryptos_toolkit.py` with a stable flag-based CLI, JSON output, and dashboard export support.
- Fixed stale GPU match accounting by resetting pass buffers before each pass and adding finite defaults.
- Corrected the research mismatch in Strategy 3 by explicitly using a hybrid clue-plus-IoC heuristic.
- Reworked the docs site to read from generated dashboard data rather than static handwritten strategy copy.
- Added `unittest` coverage for K4 invariants, Polybius/Bifid sanity, CLI behavior, and dictionary generation.
- Reframed `linux_native_suite.mojo` as a benchmark scaffold and updated the Mojo deluxe sweep to mutate work across passes.
- Added installable packaging metadata in `pyproject.toml`, optional GPU extras, and console-script entry points.
- Added a shared benchmark schema and profile catalog for GPU OpenCL, Mojo deluxe, and Mojo scaffold runners.
- Added benchmark plan/export tooling via `kryptos.benchmark_cli` plus sample plan artifacts in `runs/`.
- Added shared stage-result caching for the heavy CPU research families so Strategies 10, 12, 13, and 14 can reuse fractionation, periodic-transposition, and running-key candidate pools within one run.
- Added deterministic family-plus-preview deduping for the newer CPU candidate pools and for hydrated GPU candidate records.
- Added Strategy 14, `Displacement Route Search`, to test clue-aligned global displacement offsets on top fractionation/transposition candidates and rerank them with route-aware scoring.
- Extended the CPU benchmark profiles with `displacement_window` and `route_followup_limit`, and added a comparison artifact generator at `python -m kryptos.benchmark_compare`.
- Regenerated `runs/latest_run.json` and `docs/data/dashboard.json` so the structured outputs now reflect all 14 active strategies.

## Shared Artifacts

- `runs/latest_run.json`: structured local run output from the latest full Python sweep.
- `docs/data/dashboard.json`: dashboard payload published with the static site.
- `kryptos/catalog.py`: source-of-truth metadata for strategy descriptions, benchmark notes, and anchor data.
- `runs/benchmark_comparison.json`: bounded-run delta summary against the existing CPU/GPU baselines.

## Next High-Value Steps

- Convert the new CPU displacement-route idea into a stronger GPU hydration lane, especially around the repeated `raw_best_displacement = -9` survivors from the default 50-sweep GPU run.
- Improve smoke-profile candidate quality: the March 12 CPU smoke rerun increased unique retained candidates but did not beat the earlier top-score baseline.
- Add strategy-level preview/metric fixtures so future ranking or caching changes show regressions without rerunning the full research matrix.
- Add browser-free dashboard snapshot verification so regenerated site data is covered the same way as the benchmark and strategy outputs.
