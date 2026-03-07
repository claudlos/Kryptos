"""Runtime helpers shared by the toolkit, strategies, and benchmarks."""

from __future__ import annotations

from dataclasses import dataclass
import inspect
from typing import Any

from .constants import DEFAULT_DATASET_PROFILE, DEFAULT_SCORER_PROFILE
from .corpora import CorpusBundle, load_corpus_profile


@dataclass(slots=True)
class StrategyRuntimeConfig:
    dataset_profile: str = DEFAULT_DATASET_PROFILE
    scorer_profile: str = DEFAULT_SCORER_PROFILE
    beam_width: int = 256
    candidate_limit: int = 8
    max_post_key_length: int = 12
    width_min: int = 5
    width_max: int = 32
    _corpora: CorpusBundle | None = None

    @property
    def corpora(self) -> CorpusBundle:
        if self._corpora is None:
            self._corpora = load_corpus_profile(self.dataset_profile)
        return self._corpora


def call_strategy(module: Any, config: StrategyRuntimeConfig):
    run = module.run
    signature = inspect.signature(run)
    kwargs: dict[str, Any] = {}
    if "config" in signature.parameters:
        kwargs["config"] = config
    if "dataset_profile" in signature.parameters:
        kwargs["dataset_profile"] = config.dataset_profile
    if "scorer_profile" in signature.parameters:
        kwargs["scorer_profile"] = config.scorer_profile
    return run(**kwargs)