from __future__ import annotations

import argparse
import importlib
import json
from time import perf_counter

from kryptos.catalog import list_strategy_specs
from kryptos.common import ensure_top_candidates, format_result
from kryptos.constants import DATASET_PROFILES, DEFAULT_DATASET_PROFILE, DEFAULT_SCORER_PROFILE, SCORER_PROFILES
from kryptos.dashboard import build_dashboard_payload, serialize_run_summary, write_json
from kryptos.ledger import build_adaptive_guidance, build_experiment_plan, build_ledger_summary, load_ledger, merge_run_into_ledger, write_ledger
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
    parser.add_argument("--plan-output", help="Write ranked recommended next experiments to a JSON file.")
    parser.add_argument("--ledger-input", help="Load adaptive search guidance from an existing research ledger JSON file.")
    parser.add_argument("--ledger-output", help="Merge retained candidates into a persistent research ledger JSON file.")
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


def build_runtime_config(args: argparse.Namespace, *, adaptive_guidance: dict[str, object] | None = None) -> StrategyRuntimeConfig:
    return StrategyRuntimeConfig(
        dataset_profile=args.dataset_profile,
        scorer_profile=args.scorer_profile,
        beam_width=max(args.beam_width, 8),
        candidate_limit=max(args.candidate_limit, 1),
        adaptive_guidance=dict(adaptive_guidance or {}),
    )


def load_guidance_ledger(args: argparse.Namespace) -> dict[str, object] | None:
    ledger_path = args.ledger_input or args.ledger_output
    if not ledger_path:
        return None
    return load_ledger(ledger_path)


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
    guidance_ledger = load_guidance_ledger(args)
    adaptive_guidance = build_adaptive_guidance(guidance_ledger or {}) if guidance_ledger is not None else {}
    config = build_runtime_config(args, adaptive_guidance=adaptive_guidance)
    results = run_selection(selection, config)
    run_summary = serialize_run_summary(results, selection)
    run_summary["dataset_profile"] = config.dataset_profile
    run_summary["scorer_profile"] = config.scorer_profile
    if config.adaptive_enabled:
        run_summary["adaptive_guidance"] = adaptive_guidance

    research_memory = build_ledger_summary(guidance_ledger) if guidance_ledger is not None and guidance_ledger.get("candidate_count") else None
    if args.ledger_output:
        ledger = merge_run_into_ledger(load_ledger(args.ledger_output), run_summary)
        write_ledger(args.ledger_output, ledger)
        research_memory = build_ledger_summary(ledger)
    elif args.plan_output and research_memory is None:
        research_memory = build_ledger_summary(merge_run_into_ledger(guidance_ledger, run_summary))

    experiment_plan = research_memory.get("experiment_plan") if research_memory else None
    if experiment_plan is not None:
        run_summary["experiment_plan"] = experiment_plan

    if args.output:
        write_json(args.output, run_summary)

    if args.plan_output:
        write_json(args.plan_output, experiment_plan or build_experiment_plan(guidance_ledger or {}))

    if args.dashboard_output:
        write_json(args.dashboard_output, build_dashboard_payload(run_summary, research_memory=research_memory))

    if args.json:
        print(json.dumps(run_summary, indent=2))
        return

    for index, result in enumerate(results):
        if index:
            print("\n" + "=" * 72)
        print(format_result(result))


if __name__ == "__main__":
    main()
