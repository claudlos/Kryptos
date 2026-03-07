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

## Shared Artifacts

- `runs/latest_run.json`: structured local run output from the latest full Python sweep.
- `docs/data/dashboard.json`: dashboard payload published with the static site.
- `kryptos/catalog.py`: source-of-truth metadata for strategy descriptions, benchmark notes, and anchor data.

## Next High-Value Steps

- Add strategy-level fixtures for expected previews and metrics so regressions show up without rerunning the full suite manually.
- Build a repeatable benchmark command for the GPU and Mojo runners that exports comparable machine metadata.
- Split heavyweight strategies into configurable search profiles so quick smoke tests and deeper research runs use the same code path.
- Add browser-free site verification, such as snapshotting the generated dashboard JSON schema in tests.
