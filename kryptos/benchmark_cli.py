"""Unified benchmark entry point for CPU, GPU, and Mojo benchmark runners."""

from __future__ import annotations

import argparse
from importlib import resources
import importlib
import json
import subprocess
import sys
import time
from typing import Any

from .benchmarking import build_benchmark_record, finalize_benchmark_record, get_benchmark_profile, list_runners
from .catalog import get_strategy_spec
from .common import ensure_top_candidates
from .dashboard import serialize_run_summary, write_json
from .paths import DEFAULT_DICTIONARY_PATH, resolve_existing_path
from .runtime import StrategyRuntimeConfig, call_strategy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run or plan standardized Kryptos benchmark executions.")
    parser.add_argument("--runner", choices=list_runners(), required=True, help="Benchmark runner to use.")
    parser.add_argument("--profile", help="Named benchmark profile for the selected runner.")
    parser.add_argument("--dictionary", default=str(DEFAULT_DICTIONARY_PATH), help="Dictionary path for dictionary-based runners.")
    parser.add_argument("--mojo-binary", default="mojo", help="Mojo executable to use for Mojo benchmark runners.")
    parser.add_argument("--script", help="Override the default runner script path.")
    parser.add_argument("--passes", type=int, help="GPU override: passes to run.")
    parser.add_argument("--sweeps-per-pass", type=int, help="GPU override: sweeps per pass.")
    parser.add_argument("--copies-per-sweep", type=int, help="GPU override: copies per sweep.")
    parser.add_argument("--match-limit", type=int, help="GPU override: match limit.")
    parser.add_argument("--score-threshold", type=int, help="GPU override: minimum candidate score to retain.")
    parser.add_argument("--top-candidate-limit", type=int, help="GPU override: maximum hydrated candidates to surface.")
    parser.add_argument("--hydrate-limit", type=int, help="GPU override: maximum raw GPU candidates to hydrate on CPU.")
    parser.add_argument("--min-anchor-hits", type=int, help="GPU override: minimum anchor-position character matches required before hydration.")
    parser.add_argument("--max-post-key-length", type=int, help="Shared override: longest repeating-key layer to infer.")
    parser.add_argument("--beam-width", type=int, help="CPU override: beam width for hybrid search.")
    parser.add_argument("--candidate-limit", type=int, help="CPU override: retained candidates per strategy.")
    parser.add_argument("--width-max", type=int, help="CPU override: largest periodic transposition width.")
    parser.add_argument("--dataset-profile", help="CPU override: dataset profile.")
    parser.add_argument("--scorer-profile", help="CPU override: scorer profile.")
    parser.add_argument("--strategy-ids", nargs="+", help="CPU override: explicit strategy IDs to benchmark.")
    parser.add_argument("--sweep-count", type=int, help="Mojo deluxe override: number of mutation sweeps.")
    parser.add_argument("--outer-iterations", type=int, help="Mojo scaffold override: outer loop count.")
    parser.add_argument("--inner-iterations", type=int, help="Mojo scaffold override: inner loop count.")
    parser.add_argument("--plan-only", action="store_true", help="Emit the resolved benchmark plan without executing it.")
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout.")
    parser.add_argument("--output", help="Write the resolved or completed benchmark record to a JSON file.")
    return parser.parse_args()


def resolve_profile_name(runner: str, requested: str | None) -> str:
    return requested or "default"


def resolve_profile_config(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    profile_name = resolve_profile_name(args.runner, args.profile)
    profile = get_benchmark_profile(args.runner, profile_name)
    config = {key: value for key, value in profile.items() if key != "description"}
    if args.runner == "cpu-strategy":
        if args.dataset_profile is not None:
            config["dataset_profile"] = args.dataset_profile
        if args.scorer_profile is not None:
            config["scorer_profile"] = args.scorer_profile
        if args.strategy_ids is not None:
            config["strategy_ids"] = args.strategy_ids
        if args.beam_width is not None:
            config["beam_width"] = args.beam_width
        if args.candidate_limit is not None:
            config["candidate_limit"] = args.candidate_limit
        if args.max_post_key_length is not None:
            config["max_post_key_length"] = args.max_post_key_length
        if args.width_max is not None:
            config["width_max"] = args.width_max
    elif args.runner == "gpu-opencl":
        if args.passes is not None:
            config["passes"] = args.passes
        if args.sweeps_per_pass is not None:
            config["sweeps_per_pass"] = args.sweeps_per_pass
        if args.copies_per_sweep is not None:
            config["copies_per_sweep"] = args.copies_per_sweep
        if args.match_limit is not None:
            config["match_limit"] = args.match_limit
        if args.score_threshold is not None:
            config["score_threshold"] = args.score_threshold
        if args.top_candidate_limit is not None:
            config["top_candidate_limit"] = args.top_candidate_limit
        if args.hydrate_limit is not None:
            config["hydrate_limit"] = args.hydrate_limit
        if args.min_anchor_hits is not None:
            config["min_anchor_hits"] = args.min_anchor_hits
        if args.max_post_key_length is not None:
            config["max_post_key_length"] = args.max_post_key_length
    elif args.runner == "mojo-deluxe":
        if args.sweep_count is not None:
            config["sweep_count"] = args.sweep_count
    elif args.runner == "mojo-scaffold":
        if args.outer_iterations is not None:
            config["outer_iterations"] = args.outer_iterations
        if args.inner_iterations is not None:
            config["inner_iterations"] = args.inner_iterations
    return profile_name, config


def packaged_runner_path(filename: str) -> str:
    return str(resources.files("kryptos").joinpath(f"data/{filename}"))


def resolve_runner_script(args: argparse.Namespace) -> str | None:
    if args.script:
        return str(resolve_existing_path(args.script))
    if args.runner == "mojo-deluxe":
        repo_path = resolve_existing_path("kryptos_deluxe_suite.mojo")
        if repo_path.exists():
            return str(repo_path)
        return packaged_runner_path("kryptos_deluxe_suite.mojo")
    if args.runner == "mojo-scaffold":
        repo_path = resolve_existing_path("linux_native_suite.mojo")
        if repo_path.exists():
            return str(repo_path)
        return packaged_runner_path("linux_native_suite.mojo")
    return None


def build_command(args: argparse.Namespace, profile_name: str, config: dict[str, Any]) -> list[str]:
    if args.runner == "cpu-strategy":
        command = [sys.executable, "-m", "kryptos.benchmark_cli", "--runner", "cpu-strategy", "--profile", profile_name, "--json"]
        command.extend(["--dataset-profile", str(config["dataset_profile"])])
        command.extend(["--scorer-profile", str(config["scorer_profile"])])
        command.extend(["--beam-width", str(config["beam_width"])])
        command.extend(["--candidate-limit", str(config["candidate_limit"])])
        command.extend(["--max-post-key-length", str(config["max_post_key_length"])])
        command.extend(["--width-max", str(config["width_max"])])
        if config["strategy_ids"]:
            command.append("--strategy-ids")
            command.extend(str(strategy_id) for strategy_id in config["strategy_ids"])
        return command
    if args.runner == "gpu-opencl":
        command = [sys.executable, "-m", "gpu_opencl_suite", "--profile", profile_name, "--json", "--dictionary", str(resolve_existing_path(args.dictionary))]
        if args.passes is not None:
            command.extend(["--passes", str(args.passes)])
        if args.sweeps_per_pass is not None:
            command.extend(["--sweeps-per-pass", str(args.sweeps_per_pass)])
        if args.copies_per_sweep is not None:
            command.extend(["--copies-per-sweep", str(args.copies_per_sweep)])
        if args.match_limit is not None:
            command.extend(["--match-limit", str(args.match_limit)])
        if args.score_threshold is not None:
            command.extend(["--score-threshold", str(args.score_threshold)])
        if args.top_candidate_limit is not None:
            command.extend(["--top-candidates", str(args.top_candidate_limit)])
        if args.hydrate_limit is not None:
            command.extend(["--hydrate-limit", str(args.hydrate_limit)])
        if args.min_anchor_hits is not None:
            command.extend(["--min-anchor-hits", str(args.min_anchor_hits)])
        if args.max_post_key_length is not None:
            command.extend(["--max-post-key-length", str(args.max_post_key_length)])
        return command

    script_path = resolve_runner_script(args)
    if args.runner == "mojo-deluxe":
        return [
            args.mojo_binary,
            "run",
            str(script_path),
            str(config["thread_id"]),
            str(config["sweep_count"]),
            str(resolve_existing_path(args.dictionary)),
            profile_name,
        ]
    if args.runner == "mojo-scaffold":
        return [
            args.mojo_binary,
            "run",
            str(script_path),
            str(config["outer_iterations"]),
            str(config["inner_iterations"]),
            profile_name,
        ]
    raise ValueError(f"Unsupported runner: {args.runner}")


def parse_mojo_markers(stdout: str) -> dict[str, str]:
    markers: dict[str, str] = {}
    for line in stdout.splitlines():
        if "BENCHMARK_" not in line or "=" not in line:
            continue
        marker_text = line.split("BENCHMARK_", 1)[1]
        key, value = marker_text.split("=", 1)
        markers[key.strip()] = value.strip()
    return markers


def run_gpu_command(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    payload = json.loads(completed.stdout)
    payload["raw_stdout"] = completed.stdout
    payload["raw_stderr"] = completed.stderr
    return payload


def run_cpu_strategy(profile_name: str, config: dict[str, Any], command: list[str]) -> dict[str, Any]:
    runtime = StrategyRuntimeConfig(
        dataset_profile=str(config["dataset_profile"]),
        scorer_profile=str(config["scorer_profile"]),
        beam_width=int(config["beam_width"]),
        candidate_limit=int(config["candidate_limit"]),
        max_post_key_length=int(config["max_post_key_length"]),
        width_max=int(config["width_max"]),
    )
    started = time.time()
    results = []
    pass_summaries = []
    for strategy_id in config["strategy_ids"]:
        spec = get_strategy_spec(str(strategy_id))
        module = importlib.import_module(spec["module"])
        pass_started = time.time()
        result = call_strategy(module, runtime)
        result.metrics.elapsed_seconds = round(time.time() - pass_started, 6)
        ensure_top_candidates(result, scorer_profile=runtime.scorer_profile)
        results.append(result)
        pass_summaries.append(
            {
                "strategy_id": strategy_id,
                "attempts": result.metrics.attempts,
                "unique_attempts": result.metrics.unique_attempts,
                "elapsed_seconds": result.metrics.elapsed_seconds,
                "top_candidate": result.artifacts["top_candidates"][0],
            }
        )
    record = build_benchmark_record("cpu-strategy", profile_name, config, command=command)
    run_summary = serialize_run_summary(results, ",".join(config["strategy_ids"]))
    return finalize_benchmark_record(
        record,
        attempts=sum(result.metrics.attempts for result in results),
        unique_attempts=sum(result.metrics.unique_attempts or 0 for result in results),
        elapsed_seconds=time.time() - started,
        pass_summaries=pass_summaries,
        artifacts={
            "strategy_results": run_summary,
            "top_candidates": [result.artifacts["top_candidates"][0] for result in results],
        },
    )


def run_mojo_command(args: argparse.Namespace, profile_name: str, config: dict[str, Any], command: list[str]) -> dict[str, Any]:
    started = time.time()
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    elapsed = time.time() - started
    markers = parse_mojo_markers(completed.stdout)
    record = build_benchmark_record(
        args.runner,
        profile_name,
        {
            **config,
            "dictionary": str(resolve_existing_path(args.dictionary)) if args.runner == "mojo-deluxe" else None,
            "script": resolve_runner_script(args),
        },
        command=command,
    )

    if args.runner == "mojo-deluxe":
        attempts = int(markers.get("TOTAL_ATTEMPTS", "0"))
        unique_attempts = int(markers.get("UNIQUE_ATTEMPTS", str(attempts)))
        match_count = int(markers.get("MATCHES", "0"))
        artifacts = {
            "dictionary_path": markers.get("DICTIONARY_PATH", str(resolve_existing_path(args.dictionary))),
            "thread_id": markers.get("THREAD_ID", config["thread_id"]),
        }
    else:
        attempts = int(markers.get("TOTAL_ITERATIONS", "0"))
        unique_attempts = attempts
        match_count = None
        artifacts = {
            "outer_iterations": int(markers.get("OUTER_ITERATIONS", str(config["outer_iterations"]))),
            "inner_iterations": int(markers.get("INNER_ITERATIONS", str(config["inner_iterations"]))),
            "metric_kind": "iterations",
        }

    return finalize_benchmark_record(
        record,
        attempts=attempts,
        unique_attempts=unique_attempts,
        elapsed_seconds=elapsed,
        match_count=match_count,
        artifacts=artifacts,
        raw_stdout=completed.stdout,
        raw_stderr=completed.stderr,
    )


def build_plan_record(args: argparse.Namespace, profile_name: str, config: dict[str, Any], command: list[str]) -> dict[str, Any]:
    record = build_benchmark_record(args.runner, profile_name, config, command=command, notes=["Plan-only execution; runner not launched."])
    if args.runner == "cpu-strategy":
        record["artifacts"] = {
            "strategy_ids": config["strategy_ids"],
            "dataset_profile": config["dataset_profile"],
            "scorer_profile": config["scorer_profile"],
        }
    else:
        record["artifacts"] = {"planned_dictionary": str(resolve_existing_path(args.dictionary)) if args.runner != "mojo-scaffold" else None}
    return record


def main() -> None:
    args = parse_args()
    profile_name, config = resolve_profile_config(args)
    command = build_command(args, profile_name, config)

    if args.plan_only:
        payload = build_plan_record(args, profile_name, config, command)
    elif args.runner == "cpu-strategy":
        payload = run_cpu_strategy(profile_name, config, command)
    elif args.runner == "gpu-opencl":
        payload = run_gpu_command(command)
    else:
        payload = run_mojo_command(args, profile_name, config, command)

    if args.output:
        write_json(args.output, payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()