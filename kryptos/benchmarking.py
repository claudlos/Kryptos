"""Shared benchmark profiles and machine-readable benchmark records."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import socket
import sys
from typing import Any

SCHEMA_VERSION = "1.1"

BENCHMARK_PROFILES: dict[str, dict[str, dict[str, Any]]] = {
    "cpu-strategy": {
        "smoke": {
            "description": "Quick fixture-first pass across the new CPU strategy families.",
            "strategy_ids": ["10", "11", "12", "13", "14"],
            "dataset_profile": "public",
            "scorer_profile": "anchor-first",
            "beam_width": 64,
            "candidate_limit": 4,
            "max_post_key_length": 8,
            "width_max": 12,
            "displacement_window": 12,
            "route_followup_limit": 2,
        },
        "default": {
            "description": "Repository default CPU strategy configuration for method reconstruction work.",
            "strategy_ids": ["10", "11", "12", "13", "14"],
            "dataset_profile": "full-public",
            "scorer_profile": "anchor-first",
            "beam_width": 256,
            "candidate_limit": 8,
            "max_post_key_length": 12,
            "width_max": 32,
            "displacement_window": 24,
            "route_followup_limit": 3,
        },
        "deep": {
            "description": "Broader CPU strategy search with larger beams and more retained candidates.",
            "strategy_ids": ["10", "11", "12", "13", "14"],
            "dataset_profile": "full-public",
            "scorer_profile": "geo-route",
            "beam_width": 4096,
            "candidate_limit": 12,
            "max_post_key_length": 12,
            "width_max": 32,
            "displacement_window": 24,
            "route_followup_limit": 5,
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
            "focus_budget": 4,
            "focus_seed_limit": 2,
            "focus_neighbor_span": 1,
            "duty_cycle_percent": 100,
            "continuous": False,
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
            "focus_budget": 24,
            "focus_seed_limit": 4,
            "focus_neighbor_span": 2,
            "duty_cycle_percent": 100,
            "continuous": False,
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
            "focus_budget": 48,
            "focus_seed_limit": 6,
            "focus_neighbor_span": 3,
            "duty_cycle_percent": 100,
            "continuous": False,
        },
        "background-69": {
            "description": "Background-friendly continuous GPU sweep that duty-cycles kernel launches to target about 69 percent device time.",
            "passes": 1,
            "sweeps_per_pass": 8,
            "copies_per_sweep": 8,
            "match_limit": 256,
            "score_threshold": 1700,
            "top_candidate_limit": 12,
            "hydrate_limit": 24,
            "min_anchor_hits": 5,
            "max_post_key_length": 12,
            "focus_budget": 8,
            "focus_seed_limit": 2,
            "focus_neighbor_span": 1,
            "duty_cycle_percent": 69,
            "continuous": True,
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


def load_benchmark_record(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    return json.loads(source.read_text(encoding="utf-8"))


def candidate_family_signature(candidate: dict[str, Any]) -> tuple[tuple[str, ...], str]:
    transform_chain = tuple(str(step).split(":", 1)[0] for step in candidate.get("transform_chain", []))
    preview = str(candidate.get("preview") or candidate.get("best_preview") or "")
    return transform_chain, preview


def extract_record_candidates(record: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = record.get("artifacts", {})
    if str(record.get("runner") or "") == "cpu-strategy":
        strategy_results = artifacts.get("strategy_results", {})
        results = strategy_results.get("results", [])
        candidates = [
            candidate
            for result in results
            for candidate in result.get("artifacts", {}).get("top_candidates", [])
        ]
        if candidates:
            return candidates
    top_candidates = artifacts.get("top_candidates")
    if isinstance(top_candidates, list):
        return list(top_candidates)
    candidates = []
    for summary in record.get("execution", {}).get("pass_summaries", []):
        for candidate in summary.get("top_candidates", []):
            candidates.append(candidate)
    return candidates


def summarize_benchmark_record(record: dict[str, Any]) -> dict[str, Any]:
    candidates = extract_record_candidates(record)
    matched_clues = sorted({
        str(clue)
        for candidate in candidates
        for clue in candidate.get("matched_clues", [])
    })
    unique_candidate_count = len({candidate_family_signature(candidate) for candidate in candidates})
    top_score = 0
    if candidates:
        top_score = max(int(candidate.get("total_score", candidate.get("best_score", 0))) for candidate in candidates)
    return {
        "runner": record.get("runner"),
        "profile": record.get("profile", {}).get("name"),
        "attempts_per_second": record.get("execution", {}).get("attempts_per_second"),
        "candidate_count": len(candidates),
        "unique_candidate_count": unique_candidate_count,
        "top_score": top_score,
        "matched_clues": matched_clues,
        "matched_clue_count": len(matched_clues),
    }


def compare_benchmark_records(
    label: str,
    baseline_record: dict[str, Any],
    current_record: dict[str, Any],
    *,
    baseline_path: str | Path,
    current_path: str | Path,
) -> dict[str, Any]:
    baseline = summarize_benchmark_record(baseline_record)
    current = summarize_benchmark_record(current_record)
    baseline_rate = baseline.get("attempts_per_second")
    current_rate = current.get("attempts_per_second")
    deltas = {
        "top_score": int(current["top_score"]) - int(baseline["top_score"]),
        "matched_clue_count": int(current["matched_clue_count"]) - int(baseline["matched_clue_count"]),
        "unique_candidate_count": int(current["unique_candidate_count"]) - int(baseline["unique_candidate_count"]),
        "attempts_per_second": (
            round(float(current_rate) - float(baseline_rate), 6)
            if baseline_rate is not None and current_rate is not None
            else None
        ),
    }
    quality_improved = any(
        deltas[key] > 0 for key in ("top_score", "matched_clue_count", "unique_candidate_count")
    )
    throughput_improved = bool(deltas["attempts_per_second"] is not None and deltas["attempts_per_second"] > 0)
    return {
        "label": label,
        "baseline_path": str(baseline_path),
        "current_path": str(current_path),
        "baseline": baseline,
        "current": current,
        "deltas": deltas,
        "improved": quality_improved,
        "quality_improved": quality_improved,
        "throughput_improved": throughput_improved,
    }


def build_benchmark_comparison(pairs: list[dict[str, str]]) -> dict[str, Any]:
    comparisons = []
    for pair in pairs:
        baseline_path = Path(pair["baseline"])
        current_path = Path(pair["current"])
        comparisons.append(
            compare_benchmark_records(
                pair["label"],
                load_benchmark_record(baseline_path),
                load_benchmark_record(current_path),
                baseline_path=baseline_path,
                current_path=current_path,
            )
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "comparisons": comparisons,
    }
