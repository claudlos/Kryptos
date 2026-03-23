from __future__ import annotations

import itertools

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_quagmire_tableau,
    clue_overlap_score,
    decrypt_quagmire_autokey,
    extract_clue_hits,
    format_result,
    preview_text,
)
from kryptos.constants import K4
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("6")
PRIMERS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "CIA", "ILLUSION"]


def run() -> StrategyResult:
    tableau = build_quagmire_tableau()
    candidates: dict[str, str] = {}
    for primer_one, primer_two in itertools.product(PRIMERS, repeat=2):
        for mode_one in ("plain", "cipher"):
            for mode_two in ("plain", "cipher"):
                label = f"L1={primer_one} ({mode_one}), L2={primer_two} ({mode_two})"
                intermediate = decrypt_quagmire_autokey(K4, primer_two, mode=mode_two, tableau=tableau)
                candidates[label] = decrypt_quagmire_autokey(intermediate, primer_one, mode=mode_one, tableau=tableau)

    best_label, best_text = max(candidates.items(), key=lambda item: clue_overlap_score(item[1]))
    matched_label = next((label for label, text in candidates.items() if extract_clue_hits(text)), None)
    matched_clues = extract_clue_hits(candidates[matched_label]) if matched_label else []
    summary = (
        f"Matched {', '.join(matched_clues)} with {matched_label}."
        if matched_clues
        else "No chained autokey primer pair surfaced the known K4 anchors."
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
        notes=[f"Evaluated {len(PRIMERS) ** 2} primer pairs across four mode combinations each."],
        artifacts={"best_candidate": best_label},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
