from __future__ import annotations

import argparse
import importlib
import json
from time import perf_counter

from kryptos.catalog import list_strategy_specs
from kryptos.common import ensure_top_candidates, format_result
from kryptos.constants import DATASET_PROFILES, DEFAULT_DATASET_PROFILE, DEFAULT_SCORER_PROFILE, SCORER_PROFILES
from kryptos.dashboard import build_dashboard_payload, serialize_run_summary, write_json
from kryptos.runtime import StrategyRuntimeConfig, call_strategy

STRATEGY_SPECS = list_strategy_specs()
STRATEGY_MODULES = {spec["id"]: spec["module"] for spec in STRATEGY_SPECS}
STRATEGY_CHOICES = [spec["id"] for spec in STRATEGY_SPECS] + ["all"]


def load_strategy_module(strategy_id: str):
    return importlib.import_module(STRATEGY_MODULES[strategy_id])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Kryptos K4 cryptanalysis toolkit")
    parser.add_argument("legacy_strategy", nargs="?", choices=STRATEGY_CHOICES, help="Backward-compatible positional strategy selector.")
    parser.add_argument("-s", "--strategy", choices=STRATEGY_CHOICES, help="Strategy number to run, or 'all'. Defaults to 'all'.")
    parser.add_argument("--list-strategies", action="store_true", help="List available strategies and exit.")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON instead of plain text.")
    parser.add_argument("--output", help="Write the structured run summary to a JSON file.")
    parser.add_argument("--dashboard-output", help="Write dashboard data, including the latest run, to a JSON file.")
    parser.add_argument("--dataset-profile", choices=DATASET_PROFILES, default=DEFAULT_DATASET_PROFILE, help="Corpus bundle profile to load for corpus-backed strategies.")
    parser.add_argument("--scorer-profile", choices=SCORER_PROFILES, default=DEFAULT_SCORER_PROFILE, help="Candidate scoring weights to use.")
    parser.add_argument("--beam-width", type=int, default=256, help="Beam width for hybrid strategy exploration.")
    parser.add_argument("--candidate-limit", type=int, default=8, help="Maximum retained candidates per strategy.")
    return parser.parse_args()


def resolve_strategy_selection(args: argparse.Namespace) -> str:
    if args.strategy and args.legacy_strategy and args.strategy != args.legacy_strategy:
        raise SystemExit("Positional strategy and --strategy disagree. Use one selector.")
    selection = args.strategy or args.legacy_strategy or "all"
    return selection


def list_strategies() -> list[dict[str, str]]:
    return STRATEGY_SPECS


def build_runtime_config(args: argparse.Namespace) -> StrategyRuntimeConfig:
    return StrategyRuntimeConfig(
        dataset_profile=args.dataset_profile,
        scorer_profile=args.scorer_profile,
        beam_width=max(args.beam_width, 8),
        candidate_limit=max(args.candidate_limit, 1),
    )


def run_selection(selection: str, config: StrategyRuntimeConfig):
    strategy_ids = [spec["id"] for spec in STRATEGY_SPECS] if selection == "all" else [selection]
    results = []
    for strategy_id in strategy_ids:
        module = load_strategy_module(strategy_id)
        started = perf_counter()
        result = call_strategy(module, config)
        result.metrics.elapsed_seconds = round(perf_counter() - started, 6)
        result.notes.append(f"dataset_profile={config.dataset_profile}; scorer_profile={config.scorer_profile}")
        ensure_top_candidates(result, scorer_profile=config.scorer_profile)
        results.append(result)
    return results


def main() -> None:
    args = parse_args()
    if args.list_strategies:
        payload = list_strategies()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            for spec in payload:
                print(f"[{spec['id']}] {spec['name']}: {spec['objective']}")
        return

    selection = resolve_strategy_selection(args)
    config = build_runtime_config(args)
    results = run_selection(selection, config)
    run_summary = serialize_run_summary(results, selection)
    run_summary["dataset_profile"] = config.dataset_profile
    run_summary["scorer_profile"] = config.scorer_profile

    if args.output:
        write_json(args.output, run_summary)

    if args.dashboard_output:
        write_json(args.dashboard_output, build_dashboard_payload(run_summary))

    if args.json:
        print(json.dumps(run_summary, indent=2))
        return

    for index, result in enumerate(results):
        if index:
            print("\n" + "=" * 72)
        print(format_result(result))


if __name__ == "__main__":
    main()