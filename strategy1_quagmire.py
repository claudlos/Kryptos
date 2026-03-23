from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_quagmire_tableau,
    clue_overlap_score,
    decrypt_quagmire_running,
    extract_clue_hits,
    format_result,
    preview_text,
)
from kryptos.constants import K1_PT, K2_PT, K3_PT, K4
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("1")


def run() -> StrategyResult:
    tableau = build_quagmire_tableau()
    candidates = {
        "K1 Plaintext": decrypt_quagmire_running(K4, K1_PT, tableau),
        "K2 Plaintext": decrypt_quagmire_running(K4, K2_PT, tableau),
        "K3 Plaintext": decrypt_quagmire_running(K4, K3_PT, tableau),
    }
    best_label, best_text = max(candidates.items(), key=lambda item: clue_overlap_score(item[1]))
    matched_label = next((label for label, text in candidates.items() if extract_clue_hits(text)), None)
    matched_clues = extract_clue_hits(candidates[matched_label]) if matched_label else []
    summary = (
        f"Matched {', '.join(matched_clues)} using {matched_label}."
        if matched_label
        else "No prior Kryptos plaintext produced the known K4 anchors as a direct running key."
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
        notes=["Checked K1, K2, and K3 plaintexts as direct repeating running keys."],
        artifacts={"samples": {label: preview_text(text) for label, text in candidates.items()}, "best_candidate": best_label},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
