"""Shared source-material loaders for running-key experiments."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .constants import K1_PT, K2_PT, K3_PT
from .paths import resolve_repo_path
from .runtime import StrategyRuntimeConfig
from .common import normalize_letters

REPO_SOURCE_FILES = (
    "HANDOFF.md",
    "README.md",
    "cryptos_conundrum_book.md",
    "kryptos_info.md",
    "kryptos_k4_solving_plan.md",
    "kryptos_research_notes.md",
    "docs/engineering-roadmap.md",
    "docs/research-new-methods-2026-03.md",
)

SYNTHETIC_SOURCES = (
    ("k1_plaintext", K1_PT),
    ("k2_plaintext", K2_PT),
    ("k3_plaintext", K3_PT),
)


def _source_entry(*, source_id: str, source_kind: str, normalized_text: str, source_path: str | None = None, resolved_path: str | None = None) -> dict[str, object]:
    return {
        "source_id": source_id,
        "source_kind": source_kind,
        "source_path": source_path,
        "resolved_path": resolved_path,
        "normalized_text": normalized_text,
    }


def load_repo_text_sources(source_paths: Iterable[str] = REPO_SOURCE_FILES) -> list[dict[str, object]]:
    sources: list[dict[str, object]] = []
    for source_path in source_paths:
        resolved = resolve_repo_path(source_path)
        text = resolved.read_text(encoding="utf-8")
        normalized = normalize_letters(text)
        if normalized:
            sources.append(
                _source_entry(
                    source_id=Path(source_path).stem,
                    source_kind="repo-text",
                    source_path=str(source_path),
                    resolved_path=str(resolved),
                    normalized_text=normalized,
                )
            )
    return sources


def load_corpus_text_sources(config: StrategyRuntimeConfig, document_ids: Iterable[str] | None = None) -> list[dict[str, object]]:
    sources: list[dict[str, object]] = []
    for document in config.corpora.select_documents(document_ids):
        if document.normalized_text:
            sources.append(
                _source_entry(
                    source_id=document.id,
                    source_kind=f"corpus:{document.kind}",
                    source_path=document.local_path,
                    resolved_path=document.resolved_path,
                    normalized_text=document.normalized_text,
                )
            )
    return sources


def load_synthetic_sources() -> list[dict[str, object]]:
    return [
        _source_entry(
            source_id=source_id,
            source_kind="solved-panel",
            source_path=source_id,
            resolved_path=source_id,
            normalized_text=normalize_letters(text),
        )
        for source_id, text in SYNTHETIC_SOURCES
        if normalize_letters(text)
    ]


def load_all_running_key_sources(
    config: StrategyRuntimeConfig,
    *,
    repo_source_paths: Iterable[str] = REPO_SOURCE_FILES,
    corpus_document_ids: Iterable[str] | None = None,
    include_repo_texts: bool = True,
    include_corpora: bool = True,
    include_solved_panels: bool = True,
    extra_source_paths: Iterable[str] = (),
) -> list[dict[str, object]]:
    sources: list[dict[str, object]] = []
    if include_repo_texts:
        sources.extend(load_repo_text_sources(repo_source_paths))
    if extra_source_paths:
        sources.extend(load_repo_text_sources(extra_source_paths))
    if include_corpora:
        sources.extend(load_corpus_text_sources(config, corpus_document_ids))
    if include_solved_panels:
        sources.extend(load_synthetic_sources())
    return sources


def summarize_sources(sources: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    summary: list[dict[str, object]] = []
    for source in sources:
        normalized_text = str(source["normalized_text"])
        summary.append(
            {
                "source_id": str(source["source_id"]),
                "source_kind": str(source["source_kind"]),
                "source_path": source.get("source_path"),
                "resolved_path": source.get("resolved_path"),
                "normalized_length": len(normalized_text),
            }
        )
    return summary
