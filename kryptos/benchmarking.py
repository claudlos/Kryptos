"""Shared benchmark profiles and machine-readable benchmark records."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import platform
import socket
import sys
from typing import Any

SCHEMA_VERSION = "1.1"

BENCHMARK_PROFILES: dict[str, dict[str, dict[str, Any]]] = {
    "cpu-strategy": {
        "smoke": {
            "description": "Quick fixture-first pass across the new CPU strategy families.",
            "strategy_ids": ["10", "11", "12", "13"],
            "dataset_profile": "public",
            "scorer_profile": "anchor-first",
            "beam_width": 64,
            "candidate_limit": 4,
            "max_post_key_length": 8,
            "width_max": 12,
        },
        "default": {
            "description": "Repository default CPU strategy configuration for method reconstruction work.",
            "strategy_ids": ["10", "11", "12", "13"],
            "dataset_profile": "full-public",
            "scorer_profile": "anchor-first",
            "beam_width": 256,
            "candidate_limit": 8,
            "max_post_key_length": 12,
            "width_max": 32,
        },
        "deep": {
            "description": "Broader CPU strategy search with larger beams and more retained candidates.",
            "strategy_ids": ["10", "11", "12", "13"],
            "dataset_profile": "full-public",
            "scorer_profile": "geo-route",
            "beam_width": 4096,
            "candidate_limit": 12,
            "max_post_key_length": 12,
            "width_max": 32,
        },
    },
    "gpu-opencl": {
        "smoke": {
            "description": "Quick kernel and device sanity check with minimal work.",
            "passes": 1,
            "sweeps_per_pass": 1,
            "copies_per_sweep": 1,
            "match_limit": 50,
            "score_threshold": 1200,
            "top_candidate_limit": 8,
            "hydrate_limit": 12,
            "min_anchor_hits": 2,
            "max_post_key_length": 8,
        },
        "default": {
            "description": "Repository default GPU sweep configuration.",
            "passes": 1,
            "sweeps_per_pass": 2000,
            "copies_per_sweep": 17,
            "match_limit": 1000,
            "score_threshold": 1700,
            "top_candidate_limit": 20,
            "hydrate_limit": 64,
            "min_anchor_hits": 5,
            "max_post_key_length": 12,
        },
        "deep": {
            "description": "Longer GPU benchmark profile for sustained throughput sampling.",
            "passes": 3,
            "sweeps_per_pass": 2000,
            "copies_per_sweep": 17,
            "match_limit": 1000,
            "score_threshold": 1700,
            "top_candidate_limit": 25,
            "hydrate_limit": 96,
            "min_anchor_hits": 5,
            "max_post_key_length": 12,
        },
    },
    "mojo-deluxe": {
        "smoke": {
            "description": "Quick mutated sweep sanity check for the Mojo deluxe runner.",
            "sweep_count": 1,
            "thread_id": "BENCH",
        },
        "default": {
            "description": "Repository default mutated sweep configuration for Mojo.",
            "sweep_count": 92,
            "thread_id": "BENCH",
        },
        "deep": {
            "description": "Longer mutated sweep profile for sustained Mojo benchmarking.",
            "sweep_count": 184,
            "thread_id": "BENCH",
        },
    },
    "mojo-scaffold": {
        "smoke": {
            "description": "Quick LLVM benchmark scaffold sanity check.",
            "outer_iterations": 100,
            "inner_iterations": 1000,
            "profile_label": "smoke",
        },
        "default": {
            "description": "Repository default LLVM benchmark scaffold configuration.",
            "outer_iterations": 1000,
            "inner_iterations": 10000,
            "profile_label": "default",
        },
        "deep": {
            "description": "Longer LLVM benchmark scaffold profile for throughput sampling.",
            "outer_iterations": 5000,
            "inner_iterations": 10000,
            "profile_label": "deep",
        },
    },
}


def list_runners() -> list[str]:
    return sorted(BENCHMARK_PROFILES)


def list_profiles(runner: str) -> list[str]:
    return sorted(BENCHMARK_PROFILES[runner])


def get_benchmark_profile(runner: str, profile_name: str) -> dict[str, Any]:
    return deepcopy(BENCHMARK_PROFILES[runner][profile_name])


def capture_host_metadata() -> dict[str, str]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }


def build_benchmark_record(
    runner: str,
    profile_name: str,
    config: dict[str, Any],
    *,
    command: list[str] | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    profile = get_benchmark_profile(runner, profile_name)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runner": runner,
        "profile": {
            "name": profile_name,
            "description": profile["description"],
            "config": config,
        },
        "host": capture_host_metadata(),
        "command": command,
        "notes": notes or [],
        "execution": {},
        "hardware": {},
        "artifacts": {},
    }


def calculate_rate(attempts: int, elapsed_seconds: float) -> float:
    if elapsed_seconds <= 0:
        return 0.0
    return round(attempts / elapsed_seconds, 6)


def finalize_benchmark_record(
    record: dict[str, Any],
    *,
    attempts: int,
    unique_attempts: int,
    elapsed_seconds: float,
    match_count: int | None = None,
    repeated_attempts: int | None = None,
    pass_summaries: list[dict[str, Any]] | None = None,
    hardware: dict[str, Any] | None = None,
    artifacts: dict[str, Any] | None = None,
    raw_stdout: str | None = None,
    raw_stderr: str | None = None,
) -> dict[str, Any]:
    record["execution"] = {
        "attempts": attempts,
        "unique_attempts": unique_attempts,
        "repeated_attempts": repeated_attempts if repeated_attempts is not None else max(attempts - unique_attempts, 0),
        "elapsed_seconds": round(elapsed_seconds, 6),
        "attempts_per_second": calculate_rate(attempts, elapsed_seconds),
        "match_count": match_count,
        "pass_summaries": pass_summaries or [],
    }
    if hardware:
        record["hardware"] = hardware
    if artifacts:
        record["artifacts"] = artifacts
    if raw_stdout is not None:
        record["raw_stdout"] = raw_stdout
    if raw_stderr is not None:
        record["raw_stderr"] = raw_stderr
    return record