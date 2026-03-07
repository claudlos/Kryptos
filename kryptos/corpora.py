"""Public corpus manifests and profile loaders for K4 strategy experiments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
import json
import re
from pathlib import Path
from typing import Iterable

from .constants import DATASET_PROFILES
from .paths import REPO_ROOT

STOPWORDS = {
    "THE",
    "AND",
    "FOR",
    "WITH",
    "THIS",
    "THAT",
    "FROM",
    "WERE",
    "WAS",
    "HAVE",
    "THERE",
    "THEY",
    "THEIR",
    "INTO",
    "ABOUT",
    "UNDER",
    "OVER",
    "BETWEEN",
}

PROFILE_DOCUMENTS: dict[str, tuple[str, ...]] = {
    "core": ("official", "general_english"),
    "public": ("official", "carter", "berlin_geo"),
    "carter": ("official", "carter", "general_english"),
    "geo": ("official", "berlin_geo", "general_english"),
    "full-public": ("official", "carter", "berlin_geo", "general_english"),
}


@dataclass(slots=True)
class CorpusDocument:
    id: str
    source_url: str
    license: str
    retrieved_at: str
    kind: str
    normalization: str
    local_path: str
    resolved_path: str
    text: str
    normalized_text: str
    words: tuple[str, ...]
    from_fixture: bool

    def metadata(self) -> dict[str, str | bool]:
        return {
            "id": self.id,
            "source_url": self.source_url,
            "license": self.license,
            "retrieved_at": self.retrieved_at,
            "kind": self.kind,
            "normalization": self.normalization,
            "local_path": self.local_path,
            "resolved_path": self.resolved_path,
            "from_fixture": self.from_fixture,
        }


@dataclass(slots=True)
class CorpusBundle:
    profile: str
    documents: tuple[CorpusDocument, ...]
    domain_terms: tuple[str, ...]
    entity_terms: tuple[str, ...]

    def document_ids(self) -> tuple[str, ...]:
        return tuple(document.id for document in self.documents)

    def metadata(self) -> list[dict[str, str | bool]]:
        return [document.metadata() for document in self.documents]

    def select_documents(self, document_ids: Iterable[str] | None = None) -> tuple[CorpusDocument, ...]:
        if document_ids is None:
            return self.documents
        allowed = set(document_ids)
        return tuple(document for document in self.documents if document.id in allowed)

    def combined_text(self, document_ids: Iterable[str] | None = None) -> str:
        return "".join(document.normalized_text for document in self.select_documents(document_ids))

    def iter_windows(self, width: int, document_ids: Iterable[str] | None = None) -> Iterable[dict[str, object]]:
        for document in self.select_documents(document_ids):
            text = document.normalized_text
            if len(text) < width:
                continue
            for offset in range(len(text) - width + 1):
                yield {
                    "document_id": document.id,
                    "offset": offset,
                    "window": text[offset:offset + width],
                }


def normalize_letters(text: str) -> str:
    return "".join(char for char in text.upper() if char.isalpha())


TOKEN_RE = re.compile(r"[A-Z][A-Z']+")


def tokenize_words(text: str) -> tuple[str, ...]:
    words = [token.replace("'", "") for token in TOKEN_RE.findall(text.upper())]
    return tuple(word for word in words if len(word) >= 3)


@lru_cache(maxsize=1)
def load_corpus_manifest() -> tuple[dict[str, str], ...]:
    manifest_path = Path(resources.files("kryptos").joinpath("data/corpora_manifest.json"))
    return tuple(json.loads(manifest_path.read_text(encoding="utf-8")))


def resolve_document_text(document_id: str, local_path: str) -> tuple[Path, str, bool]:
    full_path = REPO_ROOT / local_path
    if full_path.exists():
        return full_path, full_path.read_text(encoding="utf-8"), False
    fixture_path = Path(resources.files("kryptos").joinpath(f"data/corpora/{document_id}.txt"))
    return fixture_path, fixture_path.read_text(encoding="utf-8"), True


def build_document(entry: dict[str, str]) -> CorpusDocument:
    resolved_path, text, from_fixture = resolve_document_text(entry["id"], entry["local_path"])
    return CorpusDocument(
        id=entry["id"],
        source_url=entry["source_url"],
        license=entry["license"],
        retrieved_at=entry["retrieved_at"],
        kind=entry["kind"],
        normalization=entry["normalization"],
        local_path=entry["local_path"],
        resolved_path=str(resolved_path),
        text=text,
        normalized_text=normalize_letters(text),
        words=tokenize_words(text),
        from_fixture=from_fixture,
    )


def build_domain_terms(documents: Iterable[CorpusDocument]) -> tuple[str, ...]:
    counts: Counter[str] = Counter()
    for document in documents:
        if document.kind == "language":
            continue
        for word in document.words:
            if len(word) < 4 or word in STOPWORDS:
                continue
            counts[word] += 1
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return tuple(word for word, _count in ranked[:512])


DEFAULT_ENTITY_TERMS = {
    "ALEXANDERPLATZ",
    "BERLIN",
    "CLOCK",
    "EGYPT",
    "GIZA",
    "KRYPTOS",
    "LANGLEY",
    "LUXOR",
    "NILE",
    "TOMB",
    "WORLD",
    "ZEITUHR",
}


def build_entity_terms(documents: Iterable[CorpusDocument]) -> tuple[str, ...]:
    terms = set(DEFAULT_ENTITY_TERMS)
    for document in documents:
        if document.kind not in {"geo", "official", "historical"}:
            continue
        for word in document.words:
            if len(word) >= 5 and (word in DEFAULT_ENTITY_TERMS or word.endswith("PLATZ") or word.endswith("WALL")):
                terms.add(word)
    return tuple(sorted(terms))


@lru_cache(maxsize=None)
def load_corpus_profile(profile: str) -> CorpusBundle:
    if profile not in DATASET_PROFILES:
        raise ValueError(f"Unsupported dataset profile: {profile}")
    manifest_by_id = {entry["id"]: entry for entry in load_corpus_manifest()}
    documents = tuple(build_document(manifest_by_id[document_id]) for document_id in PROFILE_DOCUMENTS[profile])
    return CorpusBundle(
        profile=profile,
        documents=documents,
        domain_terms=build_domain_terms(documents),
        entity_terms=build_entity_terms(documents),
    )


def list_corpus_profiles() -> tuple[str, ...]:
    return DATASET_PROFILES