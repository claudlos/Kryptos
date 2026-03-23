"""Persistent research ledger for accumulating candidate evidence across runs."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable

from .catalog import list_strategy_specs
from .paths import ensure_parent, resolve_user_path

LEDGER_SCHEMA_VERSION = "1.1"
DEFAULT_TOP_CANDIDATE_LIMIT = 10
DEFAULT_RECOMMENDATION_LIMIT = 4
STAGE_FAMILY_ALIASES: dict[str, tuple[str, ...]] = {
    "bifid": ("bifid",),
    "running_key": ("running_key",),
    "periodic_transposition": ("periodic_transposition", "post_periodic_transposition"),
    "key-layer": ("key-layer", "post_vigenere", "post_autokey"),
}
PLANNER_STRATEGY_PRIORITY: dict[str, tuple[str, ...]] = {
    "bifid": ("10", "13"),
    "running_key": ("11", "13", "9", "8"),
    "periodic_transposition": ("12", "13", "10", "3"),
    "key-layer": ("10", "13", "6", "4"),
}
PLANNER_STAGE_NOTES: dict[str, dict[str, str]] = {
    "bifid": {
        "title": "Expand Bifid-led pipelines",
        "thesis": "Consensus candidates keep returning to Bifid-style seeds, so the next high-value work is deeper keyword and period validation plus downstream layering.",
    },
    "running_key": {
        "title": "Cross-check running-key leads against new corpora",
        "thesis": "The ledger has enough running-key signal to justify explicit cross-document confirmation instead of treating it as a side branch.",
    },
    "periodic_transposition": {
        "title": "Cross-validate periodic transposition leads",
        "thesis": "Periodic structure keeps surfacing in strong candidates, but it still needs wider confirmation across standalone and hybrid searches.",
    },
    "key-layer": {
        "title": "Broaden keyed post-layer follow-through",
        "thesis": "Key-layer evidence is accretive only if we keep testing favored primers and post-processing families against the same frontier candidates.",
    },
}
PLANNER_HINT_FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    "bifid": (("keywords", "preferred_keywords"), ("periods", "preferred_periods")),
    "running_key": (("documents", "preferred_documents"), ("keywords", "preferred_keywords")),
    "periodic_transposition": (("widths", "preferred_widths"), ("keywords", "preferred_keywords"), ("periods", "preferred_periods")),
    "key-layer": (("primers", "preferred_primers"), ("keywords", "preferred_keywords"), ("periods", "preferred_periods")),
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def candidate_fingerprint(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def canonicalize_transform_family(family: str) -> str:
    token = family.split(":", 1)[0].strip()
    if token == "gpu_bifid":
        return "bifid"
    return token


def _sort_tokens(values: Iterable[str]) -> list[str]:
    def key(value: str) -> tuple[int, int | str]:
        return (0, int(value)) if value.isdigit() else (1, value)

    return sorted({value for value in values if value}, key=key)


def _transform_families(transform_chain: list[str]) -> list[str]:
    return list(dict.fromkeys(canonicalize_transform_family(step) for step in transform_chain if step))


def _normalize_ledger(data: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(data or {})
    created_at = str(payload.get("created_at") or utc_now_iso())
    updated_at = str(payload.get("updated_at") or created_at)
    candidates = list(payload.get("candidates") or [])
    return {
        "schema_version": str(payload.get("schema_version") or LEDGER_SCHEMA_VERSION),
        "created_at": created_at,
        "updated_at": updated_at,
        "runs_merged": int(payload.get("runs_merged") or 0),
        "observations_merged": int(payload.get("observations_merged") or 0),
        "candidate_count": int(payload.get("candidate_count") or len(candidates)),
        "strategies_seen": _sort_tokens(payload.get("strategies_seen") or []),
        "dataset_profiles": sorted(set(payload.get("dataset_profiles") or [])),
        "scorer_profiles": sorted(set(payload.get("scorer_profiles") or [])),
        "last_run": dict(payload.get("last_run") or {}),
        "last_benchmark": dict(payload.get("last_benchmark") or {}),
        "top_candidates": list(payload.get("top_candidates") or []),
        "candidates": candidates,
    }


def load_ledger(path: str | Path) -> dict[str, Any]:
    resolved = resolve_user_path(path)
    if not resolved.exists():
        return _normalize_ledger()
    return _normalize_ledger(json.loads(resolved.read_text(encoding="utf-8")))


def write_ledger(path: str | Path, payload: dict[str, Any]) -> Path:
    destination = ensure_parent(path)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return destination


def iter_candidate_observations(run_summary: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    dataset_profile = str(run_summary.get("dataset_profile") or "")
    scorer_profile = str(run_summary.get("scorer_profile") or "")
    strategy_selection = str(run_summary.get("strategy_selection") or "")
    for result in run_summary.get("results") or []:
        artifacts = result.get("artifacts") or {}
        candidates = artifacts.get("top_candidates") or []
        for candidate in candidates:
            plaintext = str(candidate.get("plaintext") or "")
            if not plaintext:
                continue
            transform_chain = [str(step) for step in candidate.get("transform_chain") or []]
            matched_clues = [str(clue) for clue in candidate.get("matched_clues") or []]
            observations.append(
                {
                    "fingerprint": candidate_fingerprint(plaintext),
                    "plaintext": plaintext,
                    "preview": str(candidate.get("preview") or plaintext[:72]),
                    "length": len(plaintext),
                    "source_kind": "strategy-run",
                    "strategy_id": str(result.get("strategy_id") or ""),
                    "strategy_name": str(result.get("name") or ""),
                    "strategy_selection": strategy_selection,
                    "dataset_profile": dataset_profile,
                    "scorer_profile": scorer_profile,
                    "total_score": int(candidate.get("total_score") or 0),
                    "breakdown": dict(candidate.get("breakdown") or {}),
                    "transform_chain": transform_chain,
                    "transform_families": _transform_families(transform_chain),
                    "matched_clues": matched_clues,
                    "key_material": dict(candidate.get("key_material") or {}),
                    "corpus_id": str(candidate.get("corpus_id") or ""),
                }
            )
    return observations


def iter_benchmark_candidate_observations(benchmark_summary: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    runner = str(benchmark_summary.get("runner") or "")
    if runner != "gpu-opencl":
        return observations
    for candidate in (benchmark_summary.get("artifacts") or {}).get("top_candidates") or []:
        plaintext = str(candidate.get("plaintext") or "")
        if not plaintext:
            continue
        transform_chain = [str(step) for step in candidate.get("transform_chain") or []]
        matched_clues = [str(clue) for clue in candidate.get("matched_clues") or []]
        observations.append(
            {
                "fingerprint": candidate_fingerprint(plaintext),
                "plaintext": plaintext,
                "preview": str(candidate.get("best_preview") or candidate.get("preview") or plaintext[:72]),
                "length": len(plaintext),
                "source_kind": "benchmark",
                "strategy_id": runner,
                "strategy_name": "GPU OpenCL Sweep",
                "strategy_selection": str(benchmark_summary.get("profile", {}).get("name") or ""),
                "dataset_profile": "",
                "scorer_profile": "anchor-first",
                "total_score": int(candidate.get("best_score") or candidate.get("total_score") or 0),
                "breakdown": dict(candidate.get("breakdown") or {}),
                "transform_chain": transform_chain,
                "transform_families": _transform_families(transform_chain),
                "matched_clues": matched_clues,
                "key_material": dict(candidate.get("key_material") or {}),
                "corpus_id": "",
                "raw_periodic_hint": int(candidate.get("raw_periodic_hint") or 0),
                "raw_displacement_hint": int(candidate.get("raw_displacement_hint") or 0),
                "raw_layer_hint": int(candidate.get("raw_layer_hint") or 0),
                "raw_ngram_hint": int(candidate.get("raw_ngram_hint") or 0),
            }
        )
    return observations


def _summarize_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    best = dict(candidate.get("best_observation") or {})
    return {
        "fingerprint": candidate["fingerprint"],
        "preview": candidate["preview"],
        "length": candidate["length"],
        "best_score": candidate["best_score"],
        "average_score": candidate["average_score"],
        "consensus_score": candidate["consensus_score"],
        "observation_count": candidate["observation_count"],
        "run_count": candidate["run_count"],
        "strategy_count": len(candidate["strategy_ids"]),
        "strategy_ids": list(candidate["strategy_ids"]),
        "matched_clues": list(candidate["matched_clues"]),
        "corpus_ids": list(candidate["corpus_ids"]),
        "transform_families": list(candidate["transform_families"]),
        "best_strategy_id": best.get("strategy_id"),
        "best_strategy_name": best.get("strategy_name"),
        "best_transform_chain": list(best.get("transform_chain") or []),
        "best_breakdown": dict(best.get("breakdown") or {}),
    }


def _score_table(counter: Counter[Any]) -> dict[str, int]:
    return {str(key): int(value) for key, value in sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))}


def _ordered_keys(counter: Counter[Any]) -> list[Any]:
    return [key for key, _score in sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))]


def _accumulate_key_material_hints(
    value: Any,
    *,
    weight: int,
    keyword_scores: Counter[str],
    primer_scores: Counter[str],
    period_scores: Counter[int],
    width_scores: Counter[int],
) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_name = str(key).lower()
            if isinstance(nested, int):
                if key_name == "period":
                    period_scores[int(nested)] += weight
                elif key_name == "width":
                    width_scores[int(nested)] += weight
                continue
            if isinstance(nested, str):
                token = nested.upper()
                if key_name in {"keyword", "keyword_seed"}:
                    keyword_scores[token] += weight
                elif key_name in {"primer", "key"} and token.isalpha():
                    primer_scores[token] += weight
                continue
            _accumulate_key_material_hints(
                nested,
                weight=weight,
                keyword_scores=keyword_scores,
                primer_scores=primer_scores,
                period_scores=period_scores,
                width_scores=width_scores,
            )
        return
    if isinstance(value, list):
        for item in value:
            _accumulate_key_material_hints(
                item,
                weight=weight,
                keyword_scores=keyword_scores,
                primer_scores=primer_scores,
                period_scores=period_scores,
                width_scores=width_scores,
            )


def _accumulate_transform_chain_hints(
    transform_chain: list[str],
    *,
    weight: int,
    keyword_scores: Counter[str],
    primer_scores: Counter[str],
    period_scores: Counter[int],
    width_scores: Counter[int],
    document_scores: Counter[str],
) -> None:
    for step in transform_chain:
        parts = [part for part in str(step).split(":") if part]
        if not parts:
            continue
        family = canonicalize_transform_family(parts[0])
        if family == "bifid":
            if len(parts) >= 2 and parts[1].isalpha():
                keyword_scores[parts[1].upper()] += weight
            for token in parts[2:]:
                if token.startswith("period="):
                    try:
                        period_scores[int(token.split("=", 1)[1])] += weight
                    except ValueError:
                        pass
        elif family in {"periodic_transposition", "post_periodic_transposition"}:
            for token in parts[1:]:
                if token.startswith("w"):
                    try:
                        width_scores[int(token[1:])] += weight
                    except ValueError:
                        pass
        elif family == "post_autokey" and len(parts) >= 3 and parts[2].isalpha():
            primer_scores[parts[2].upper()] += weight
        elif family == "post_vigenere" and len(parts) >= 2 and parts[1].isalpha():
            primer_scores[parts[1].upper()] += weight
        elif family == "running_key" and len(parts) >= 2:
            document_scores[parts[1]] += weight


def build_adaptive_guidance(
    ledger: dict[str, Any],
    *,
    top_limit: int = DEFAULT_TOP_CANDIDATE_LIMIT,
) -> dict[str, Any]:
    normalized = _normalize_ledger(ledger)
    top_candidates = normalized["candidates"][:top_limit]
    family_scores: Counter[str] = Counter()
    stage_family_scores: Counter[str] = Counter()
    keyword_scores: Counter[str] = Counter()
    primer_scores: Counter[str] = Counter()
    period_scores: Counter[int] = Counter()
    width_scores: Counter[int] = Counter()
    document_scores: Counter[str] = Counter()

    for candidate in top_candidates:
        weight = max(int(candidate.get("consensus_score") or candidate.get("best_score") or 0), 1)
        for family in candidate.get("transform_families") or []:
            family_scores[str(family)] += weight
        best = dict(candidate.get("best_observation") or {})
        _accumulate_key_material_hints(
            best.get("key_material") or {},
            weight=weight,
            keyword_scores=keyword_scores,
            primer_scores=primer_scores,
            period_scores=period_scores,
            width_scores=width_scores,
        )
        _accumulate_transform_chain_hints(
            list(best.get("transform_chain") or []),
            weight=weight,
            keyword_scores=keyword_scores,
            primer_scores=primer_scores,
            period_scores=period_scores,
            width_scores=width_scores,
            document_scores=document_scores,
        )
        corpus_id = str(best.get("corpus_id") or "")
        if corpus_id:
            document_scores[corpus_id] += weight

        periodic_boost = int(best.get("raw_periodic_hint") or 0) + max(int(best.get("raw_displacement_hint") or 0) // 2, 0)
        if periodic_boost > 0:
            family_scores["periodic_transposition"] += periodic_boost
            family_scores["post_periodic_transposition"] += periodic_boost
            stage_family_scores["periodic_transposition"] += periodic_boost
        layer_boost = int(best.get("raw_layer_hint") or 0)
        if layer_boost > 0:
            family_scores["key-layer"] += layer_boost
            family_scores["post_vigenere"] += layer_boost
            stage_family_scores["key-layer"] += layer_boost

    for stage_family, aliases in STAGE_FAMILY_ALIASES.items():
        alias_score = max((family_scores.get(alias, 0) for alias in aliases), default=0)
        if alias_score > 0:
            stage_family_scores[stage_family] += alias_score

    guidance = {
        "enabled": bool(top_candidates),
        "source_candidate_count": len(top_candidates),
        "preferred_stage_families": [str(value) for value in _ordered_keys(stage_family_scores)],
        "stage_family_scores": _score_table(stage_family_scores),
        "preferred_transform_families": [str(value) for value in _ordered_keys(family_scores)],
        "transform_family_scores": _score_table(family_scores),
        "preferred_keywords": [str(value) for value in _ordered_keys(keyword_scores)],
        "preferred_periods": [int(value) for value in _ordered_keys(period_scores)],
        "preferred_widths": [int(value) for value in _ordered_keys(width_scores)],
        "preferred_primers": [str(value) for value in _ordered_keys(primer_scores)],
        "preferred_documents": [str(value) for value in _ordered_keys(document_scores)],
    }
    return guidance


def _strategy_catalog_index() -> dict[str, dict[str, str]]:
    return {
        str(spec["id"]): {
            "id": str(spec["id"]),
            "name": str(spec["name"]),
            "slug": str(spec.get("slug") or ""),
            "category": str(spec.get("category") or ""),
        }
        for spec in list_strategy_specs()
    }


def _matches_stage_family(candidate: dict[str, Any], stage_family: str) -> bool:
    aliases = set(STAGE_FAMILY_ALIASES.get(stage_family, (stage_family,)))
    families = {str(value) for value in candidate.get("transform_families") or []}
    return bool(families.intersection(aliases))


def _hint_values_for_family(guidance: dict[str, Any], stage_family: str, *, per_hint_limit: int = 3) -> dict[str, list[Any]]:
    hints: dict[str, list[Any]] = {}
    for hint_name, guidance_key in PLANNER_HINT_FIELDS.get(stage_family, ()):
        values = list(guidance.get(guidance_key) or [])[:per_hint_limit]
        if values:
            hints[hint_name] = values
    return hints


def _family_candidates(top_candidates: list[dict[str, Any]], stage_family: str) -> list[dict[str, Any]]:
    return [candidate for candidate in top_candidates if _matches_stage_family(candidate, stage_family)]


def _family_supporting_clues(candidates: list[dict[str, Any]]) -> list[str]:
    clues = {
        str(clue)
        for candidate in candidates
        for clue in candidate.get("matched_clues") or []
        if clue
    }
    return sorted(clues)


def _suggested_runs(strategy_ids: list[str], strategy_index: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    runs: list[dict[str, str]] = []
    for strategy_id in strategy_ids[:2]:
        strategy = strategy_index.get(strategy_id)
        if strategy is None:
            continue
        runs.append(
            {
                "strategy_id": strategy_id,
                "strategy_name": strategy["name"],
                "command": (
                    f"python kryptos_toolkit.py --strategy {strategy_id} "
                    "--ledger-input <ledger.json> --ledger-output <ledger.json> "
                    f"--output runs/strategy{strategy_id}_next.json"
                ),
            }
        )
    return runs


def build_experiment_plan(
    ledger: dict[str, Any],
    *,
    top_limit: int = DEFAULT_TOP_CANDIDATE_LIMIT,
    recommendation_limit: int = DEFAULT_RECOMMENDATION_LIMIT,
) -> dict[str, Any]:
    normalized = _normalize_ledger(ledger)
    top_candidates = normalized["candidates"][:top_limit]
    guidance = build_adaptive_guidance(normalized, top_limit=top_limit)
    if not guidance.get("enabled"):
        return {
            "enabled": False,
            "generated_at": normalized["updated_at"],
            "source_candidate_count": len(top_candidates),
            "recommended_experiments": [],
        }

    strategy_index = _strategy_catalog_index()
    recommendations: list[dict[str, Any]] = []
    stage_family_scores = guidance.get("stage_family_scores") or {}

    for stage_family in guidance.get("preferred_stage_families") or []:
        family = str(stage_family)
        if family not in PLANNER_STAGE_NOTES:
            continue
        family_candidates = _family_candidates(top_candidates, family)
        if not family_candidates:
            continue

        mapped_strategies = [strategy_id for strategy_id in PLANNER_STRATEGY_PRIORITY.get(family, ()) if strategy_id in strategy_index]
        observed_strategy_ids = sorted(
            {
                str(strategy_id)
                for candidate in family_candidates
                for strategy_id in candidate.get("strategy_ids") or []
                if strategy_id
            }
        )
        missing_strategy_ids = [strategy_id for strategy_id in mapped_strategies if strategy_id not in observed_strategy_ids]
        target_strategy_ids = missing_strategy_ids or mapped_strategies[:2]
        evidence_score = int(stage_family_scores.get(family) or 0)
        underexplored_score = len(missing_strategy_ids) * 120
        if len(observed_strategy_ids) <= 1:
            underexplored_score += 80
        if len(family_candidates) == 1:
            underexplored_score += 40

        notes = [PLANNER_STAGE_NOTES[family]["thesis"]]
        if missing_strategy_ids:
            notes.append(
                f"{len(missing_strategy_ids)} mapped strategies have not yet reinforced this family: {', '.join(missing_strategy_ids)}."
            )
        if observed_strategy_ids == ["gpu-opencl"]:
            notes.append("Current support is GPU-only, so the next pass should confirm the lead in the CPU toolkit.")

        recommendations.append(
            {
                "rank": 0,
                "stage_family": family,
                "title": PLANNER_STAGE_NOTES[family]["title"],
                "thesis": PLANNER_STAGE_NOTES[family]["thesis"],
                "priority_score": evidence_score + underexplored_score,
                "evidence_score": evidence_score,
                "underexplored_score": underexplored_score,
                "target_strategies": [strategy_index[strategy_id] for strategy_id in target_strategy_ids if strategy_id in strategy_index],
                "coverage": {
                    "candidate_count": len(family_candidates),
                    "observed_strategy_ids": observed_strategy_ids,
                    "missing_strategy_ids": missing_strategy_ids,
                    "supporting_clues": _family_supporting_clues(family_candidates),
                },
                "parameter_hints": _hint_values_for_family(guidance, family),
                "suggested_runs": _suggested_runs(target_strategy_ids, strategy_index),
                "notes": notes,
            }
        )

    recommendations.sort(
        key=lambda recommendation: (
            int(recommendation["priority_score"]),
            int(recommendation["evidence_score"]),
            recommendation["stage_family"],
        ),
        reverse=True,
    )
    for index, recommendation in enumerate(recommendations[:recommendation_limit], start=1):
        recommendation["rank"] = index

    return {
        "enabled": bool(recommendations),
        "generated_at": normalized["updated_at"],
        "source_candidate_count": len(top_candidates),
        "recommended_experiments": recommendations[:recommendation_limit],
    }


def build_ledger_summary(ledger: dict[str, Any], *, top_limit: int = DEFAULT_TOP_CANDIDATE_LIMIT) -> dict[str, Any]:
    normalized = _normalize_ledger(ledger)
    return {
        "schema_version": normalized["schema_version"],
        "updated_at": normalized["updated_at"],
        "runs_merged": normalized["runs_merged"],
        "observation_count": normalized["observations_merged"],
        "candidate_count": normalized["candidate_count"],
        "strategy_count": len(normalized["strategies_seen"]),
        "strategies_seen": list(normalized["strategies_seen"]),
        "dataset_profiles": list(normalized["dataset_profiles"]),
        "scorer_profiles": list(normalized["scorer_profiles"]),
        "adaptive_guidance": build_adaptive_guidance(normalized, top_limit=top_limit),
        "experiment_plan": build_experiment_plan(normalized, top_limit=top_limit),
        "top_candidates": [_summarize_candidate(candidate) for candidate in normalized["candidates"][:top_limit]],
    }


def _create_candidate_record(observation: dict[str, Any], observed_at: str) -> dict[str, Any]:
    return {
        "fingerprint": observation["fingerprint"],
        "plaintext": observation["plaintext"],
        "preview": observation["preview"],
        "length": observation["length"],
        "observation_count": 0,
        "run_count": 0,
        "score_sum": 0,
        "average_score": 0.0,
        "best_score": 0,
        "consensus_score": 0,
        "strategy_ids": [],
        "strategy_names": [],
        "dataset_profiles": [],
        "scorer_profiles": [],
        "matched_clues": [],
        "corpus_ids": [],
        "transform_families": [],
        "transform_chains": [],
        "first_seen_at": observed_at,
        "last_seen_at": observed_at,
        "best_observation": {},
    }


def _merge_lists(record: dict[str, Any], key: str, values: list[str], *, numeric_sort: bool = False) -> None:
    merged = set(record.get(key) or [])
    merged.update(value for value in values if value)
    record[key] = _sort_tokens(merged) if numeric_sort else sorted(merged)


def _observation_priority(observation: dict[str, Any]) -> tuple[int, int, int, int]:
    return (
        int(observation.get("total_score") or 0),
        len(observation.get("matched_clues") or []),
        len(observation.get("transform_chain") or []),
        len(observation.get("transform_families") or []),
    )


def _recompute_consensus_score(candidate: dict[str, Any]) -> int:
    return (
        int(candidate["best_score"])
        + len(candidate["strategy_ids"]) * 40
        + int(candidate["observation_count"]) * 8
        + len(candidate["matched_clues"]) * 24
        + len(candidate["transform_families"]) * 10
    )


def _merge_observations_into_ledger(
    existing_ledger: dict[str, Any] | None,
    observations: list[dict[str, Any]],
    *,
    observed_at: str,
    top_limit: int,
    strategy_ids: set[str],
    dataset_profiles: set[str],
    scorer_profiles: set[str],
    last_field: str,
    last_payload: dict[str, Any],
) -> dict[str, Any]:
    ledger = _normalize_ledger(existing_ledger)
    candidate_map = {candidate["fingerprint"]: dict(candidate) for candidate in ledger["candidates"]}
    seen_this_run: set[str] = set()

    for observation in observations:
        fingerprint = observation["fingerprint"]
        candidate = candidate_map.get(fingerprint)
        if candidate is None:
            candidate = _create_candidate_record(observation, observed_at)
            candidate_map[fingerprint] = candidate

        candidate["last_seen_at"] = observed_at
        candidate["observation_count"] = int(candidate.get("observation_count") or 0) + 1
        if fingerprint not in seen_this_run:
            candidate["run_count"] = int(candidate.get("run_count") or 0) + 1
            seen_this_run.add(fingerprint)

        candidate["score_sum"] = int(candidate.get("score_sum") or 0) + int(observation["total_score"])
        candidate["average_score"] = round(candidate["score_sum"] / candidate["observation_count"], 3)
        _merge_lists(candidate, "strategy_ids", [observation["strategy_id"]], numeric_sort=True)
        _merge_lists(candidate, "strategy_names", [observation["strategy_name"]])
        _merge_lists(candidate, "dataset_profiles", [observation["dataset_profile"]])
        _merge_lists(candidate, "scorer_profiles", [observation["scorer_profile"]])
        _merge_lists(candidate, "matched_clues", observation["matched_clues"])
        _merge_lists(candidate, "corpus_ids", [observation["corpus_id"]])
        _merge_lists(candidate, "transform_families", observation["transform_families"])
        _merge_lists(candidate, "transform_chains", [" -> ".join(observation["transform_chain"])])
        candidate["transform_chains"] = sorted(candidate["transform_chains"])[:24]

        current_best = dict(candidate.get("best_observation") or {})
        if not current_best or _observation_priority(observation) > _observation_priority(current_best):
            candidate["best_observation"] = {
                "source_kind": observation.get("source_kind"),
                "strategy_id": observation["strategy_id"],
                "strategy_name": observation["strategy_name"],
                "total_score": observation["total_score"],
                "matched_clues": list(observation["matched_clues"]),
                "breakdown": dict(observation["breakdown"]),
                "transform_chain": list(observation["transform_chain"]),
                "transform_families": list(observation["transform_families"]),
                "key_material": dict(observation["key_material"]),
                "corpus_id": observation["corpus_id"],
                "raw_periodic_hint": int(observation.get("raw_periodic_hint") or 0),
                "raw_displacement_hint": int(observation.get("raw_displacement_hint") or 0),
                "raw_layer_hint": int(observation.get("raw_layer_hint") or 0),
                "raw_ngram_hint": int(observation.get("raw_ngram_hint") or 0),
            }
            candidate["best_score"] = int(observation["total_score"])

        candidate["consensus_score"] = _recompute_consensus_score(candidate)

    candidates = sorted(
        candidate_map.values(),
        key=lambda candidate: (
            int(candidate["consensus_score"]),
            int(candidate["best_score"]),
            int(candidate["observation_count"]),
            candidate["fingerprint"],
        ),
        reverse=True,
    )

    ledger["schema_version"] = LEDGER_SCHEMA_VERSION
    ledger["updated_at"] = observed_at
    ledger["runs_merged"] = int(ledger.get("runs_merged") or 0) + 1
    ledger["observations_merged"] = int(ledger.get("observations_merged") or 0) + len(observations)
    ledger["candidate_count"] = len(candidates)
    ledger["strategies_seen"] = _sort_tokens(set(ledger.get("strategies_seen") or []).union(strategy_ids))
    ledger["dataset_profiles"] = sorted(set(ledger.get("dataset_profiles") or []).union(dataset_profiles))
    ledger["scorer_profiles"] = sorted(set(ledger.get("scorer_profiles") or []).union(scorer_profiles))
    ledger[last_field] = last_payload
    ledger["candidates"] = candidates
    ledger["top_candidates"] = [_summarize_candidate(candidate) for candidate in candidates[:top_limit]]
    return ledger


def merge_run_into_ledger(
    existing_ledger: dict[str, Any] | None,
    run_summary: dict[str, Any],
    *,
    observed_at: str | None = None,
    top_limit: int = DEFAULT_TOP_CANDIDATE_LIMIT,
) -> dict[str, Any]:
    timestamp = observed_at or utc_now_iso()
    observations = iter_candidate_observations(run_summary)
    strategy_ids = {
        str(result.get("strategy_id") or "")
        for result in run_summary.get("results") or []
        if result.get("strategy_id")
    }
    dataset_profiles = {str(run_summary["dataset_profile"])} if run_summary.get("dataset_profile") else set()
    scorer_profiles = {str(run_summary["scorer_profile"])} if run_summary.get("scorer_profile") else set()
    return _merge_observations_into_ledger(
        existing_ledger,
        observations,
        observed_at=timestamp,
        top_limit=top_limit,
        strategy_ids=strategy_ids,
        dataset_profiles=dataset_profiles,
        scorer_profiles=scorer_profiles,
        last_field="last_run",
        last_payload={
            "strategy_selection": run_summary.get("strategy_selection"),
            "dataset_profile": run_summary.get("dataset_profile"),
            "scorer_profile": run_summary.get("scorer_profile"),
            "result_count": run_summary.get("result_count"),
            "merged_candidate_observations": len(observations),
        },
    )


def merge_benchmark_into_ledger(
    existing_ledger: dict[str, Any] | None,
    benchmark_summary: dict[str, Any],
    *,
    observed_at: str | None = None,
    top_limit: int = DEFAULT_TOP_CANDIDATE_LIMIT,
) -> dict[str, Any]:
    timestamp = observed_at or utc_now_iso()
    observations = iter_benchmark_candidate_observations(benchmark_summary)
    runner = str(benchmark_summary.get("runner") or "")
    scorer_profiles = {"anchor-first"} if observations else set()
    return _merge_observations_into_ledger(
        existing_ledger,
        observations,
        observed_at=timestamp,
        top_limit=top_limit,
        strategy_ids={runner} if runner else set(),
        dataset_profiles=set(),
        scorer_profiles=scorer_profiles,
        last_field="last_benchmark",
        last_payload={
            "runner": benchmark_summary.get("runner"),
            "profile": (benchmark_summary.get("profile") or {}).get("name"),
            "merged_candidate_observations": len(observations),
            "attempts": (benchmark_summary.get("execution") or {}).get("attempts"),
        },
    )
