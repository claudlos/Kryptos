"""Runtime helpers shared by the toolkit, strategies, and benchmarks."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
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
    displacement_window: int = 24
    route_followup_limit: int = 3
    _corpora: CorpusBundle | None = None
    _stage_cache: dict[tuple[object, ...], object] = field(default_factory=dict)

    @property
    def corpora(self) -> CorpusBundle:
        if self._corpora is None:
            self._corpora = load_corpus_profile(self.dataset_profile)
        return self._corpora

    def stage_cache_key(self, stage_name: str, ciphertext: str, *parts: object) -> tuple[object, ...]:
        return (
            stage_name,
            ciphertext,
            self.dataset_profile,
            self.scorer_profile,
            self.candidate_limit,
            self.max_post_key_length,
            self.width_min,
            self.width_max,
            self.displacement_window,
            self.route_followup_limit,
            *parts,
        )

    def get_stage_cache(self, cache_key: tuple[object, ...]) -> object | None:
        value = self._stage_cache.get(cache_key)
        if value is None:
            return None
        return deepcopy(value)

    def set_stage_cache(self, cache_key: tuple[object, ...], value: object) -> object:
        cached_value = deepcopy(value)
        self._stage_cache[cache_key] = cached_value
        return deepcopy(cached_value)


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
