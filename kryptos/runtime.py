"""Runtime helpers shared by the toolkit, strategies, and benchmarks."""

from __future__ import annotations

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
    adaptive_guidance: dict[str, Any] = field(default_factory=dict)
    _corpora: CorpusBundle | None = None

    @property
    def corpora(self) -> CorpusBundle:
        if self._corpora is None:
            self._corpora = load_corpus_profile(self.dataset_profile)
        return self._corpora

    @property
    def adaptive_enabled(self) -> bool:
        return bool(self.adaptive_guidance.get("enabled"))

    def _ordered_values(self, values: list[Any], preferred: list[Any]) -> list[Any]:
        preferred_index = {value: index for index, value in enumerate(preferred)}
        ordered = sorted(
            enumerate(values),
            key=lambda item: (
                0 if item[1] in preferred_index else 1,
                preferred_index.get(item[1], item[0]),
                item[0],
            ),
        )
        return [value for _index, value in ordered]

    def ordered_keywords(self, keywords: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        preferred = [str(value) for value in self.adaptive_guidance.get("preferred_keywords") or []]
        return tuple(self._ordered_values(list(keywords), preferred))

    def ordered_primers(self, primers: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        preferred = [str(value) for value in self.adaptive_guidance.get("preferred_primers") or []]
        return tuple(self._ordered_values(list(primers), preferred))

    def ordered_periods(self, periods: tuple[int, ...] | list[int]) -> tuple[int, ...]:
        preferred = [int(value) for value in self.adaptive_guidance.get("preferred_periods") or []]
        return tuple(self._ordered_values(list(periods), preferred))

    def ordered_widths(self, widths: tuple[int, ...] | list[int]) -> tuple[int, ...]:
        preferred = [int(value) for value in self.adaptive_guidance.get("preferred_widths") or []]
        return tuple(self._ordered_values(list(widths), preferred))

    def ordered_documents(self, document_ids: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        preferred = [str(value) for value in self.adaptive_guidance.get("preferred_documents") or []]
        return tuple(self._ordered_values(list(document_ids), preferred))

    def ordered_stage_families(self, families: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        preferred = [str(value) for value in self.adaptive_guidance.get("preferred_stage_families") or []]
        return tuple(self._ordered_values(list(families), preferred))

    def _budget_bonus(self, preferred: list[str], value: str, max_extra: int) -> int:
        if value not in preferred:
            return 0
        return max(0, max_extra - preferred.index(value))

    def stage_budget_bonus(self, family: str, *, max_extra: int = 4) -> int:
        preferred = [str(value) for value in self.adaptive_guidance.get("preferred_stage_families") or []]
        return self._budget_bonus(preferred, family, max_extra)

    def transform_budget_bonus(self, family: str, *, max_extra: int = 4) -> int:
        preferred = [str(value) for value in self.adaptive_guidance.get("preferred_transform_families") or []]
        return self._budget_bonus(preferred, family, max_extra)

    def budgeted_limit(
        self,
        base: int,
        *,
        family: str,
        max_extra: int = 4,
        ceiling: int | None = None,
        use_stage_budget: bool = False,
    ) -> int:
        bonus = self.stage_budget_bonus(family, max_extra=max_extra) if use_stage_budget else self.transform_budget_bonus(family, max_extra=max_extra)
        value = base + bonus
        if ceiling is not None:
            value = min(value, ceiling)
        return max(1, value)

    def adaptive_summary(self) -> str:
        if not self.adaptive_enabled:
            return "Adaptive guidance disabled."
        stage_families = ", ".join((self.adaptive_guidance.get("preferred_stage_families") or [])[:3]) or "none"
        keywords = ", ".join((self.adaptive_guidance.get("preferred_keywords") or [])[:3]) or "none"
        periods = ", ".join(str(value) for value in (self.adaptive_guidance.get("preferred_periods") or [])[:3]) or "none"
        stage_budgets = ", ".join(
            f"{family}+{self.stage_budget_bonus(str(family))}"
            for family in (self.adaptive_guidance.get("preferred_stage_families") or [])[:2]
        ) or "none"
        return f"Adaptive guidance favored stages={stage_families}; keywords={keywords}; periods={periods}; budgets={stage_budgets}."


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
