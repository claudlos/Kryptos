"""Filesystem helpers for repository-local assets and generated outputs."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = Path(__file__).resolve().parent
DOCS_DIR = REPO_ROOT / "docs"
DOCS_DATA_DIR = DOCS_DIR / "data"
RUNS_DIR = REPO_ROOT / "runs"


def resolve_user_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    return Path.cwd() / candidate


def resolve_existing_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate
    cwd_candidate = Path.cwd() / candidate
    if cwd_candidate.exists():
        return cwd_candidate
    return REPO_ROOT / candidate


def get_packaged_dictionary_path() -> Path:
    return Path(resources.files("kryptos").joinpath("data/k4_dictionary.txt"))


def get_default_dictionary_path() -> Path:
    repo_dictionary = REPO_ROOT / "k4_dictionary.txt"
    if repo_dictionary.exists():
        return repo_dictionary
    return get_packaged_dictionary_path()


DEFAULT_DICTIONARY_PATH = get_default_dictionary_path()


def resolve_repo_path(path: str | Path) -> Path:
    return resolve_existing_path(path)


def ensure_parent(path: str | Path) -> Path:
    resolved = resolve_user_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved
