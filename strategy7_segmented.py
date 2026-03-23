from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_quagmire_tableau,
    clue_overlap_score,
    decrypt_quagmire_autokey,
    decrypt_quagmire_running,
    extract_clue_hits,
    format_result,
    preview_text,
)
from kryptos.constants import K4
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("7")
KEYWORDS = ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLIN", "CLOCK", "EAST"]


def run() -> StrategyResult:
    tableau = build_quagmire_tableau()
    segments = K4.split("W")
    candidates: dict[str, str] = {}
    for keyword in KEYWORDS:
        standard_segments = [decrypt_quagmire_running(segment, keyword, tableau) for segment in segments]
        candidates[f"{keyword} segmented running key"] = "W".join(standard_segments)
        autokey_segments = [decrypt_quagmire_autokey(segment, keyword, mode="plain", tableau=tableau) for segment in segments]
        candidates[f"{keyword} segmented autokey"] = "W".join(autokey_segments)

    best_label, best_text = max(candidates.items(), key=lambda item: clue_overlap_score(item[1]))
    matched_label = next((label for label, text in candidates.items() if extract_clue_hits(text)), None)
    matched_clues = extract_clue_hits(candidates[matched_label]) if matched_label else []
    summary = (
        f"Matched {', '.join(matched_clues)} with {matched_label}."
        if matched_clues
        else "Resetting the cipher at 'W' boundaries did not recover the known anchors."
    )
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status="match" if matched_clues else "no_match",
        summary=summary,
        best_preview=preview_text(best_text),
        matched_clues=matched_clues,
        metrics=SearchMetrics(attempts=len(candidates), unique_attempts=len(candidates)),
        notes=[f"Split K4 into {len(segments)} segments on 'W'."],
        artifacts={"segment_lengths": [len(segment) for segment in segments], "best_candidate": best_label},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
