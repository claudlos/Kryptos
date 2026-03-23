from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_quagmire_tableau,
    clue_overlap_score,
    decrypt_quagmire_running,
    decrypt_vigenere_standard,
    extract_clue_hits,
    format_result,
    preview_text,
)
from kryptos.constants import K1_PT, K2_PT, K3_PT, K4
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("8")
KEY_MATERIAL = {
    "K1 Plaintext": K1_PT,
    "K2 Plaintext": K2_PT,
    "K3 Plaintext": K3_PT,
    "KRYPTOS Primer": "KRYPTOS",
}


def run() -> StrategyResult:
    tableau = build_quagmire_tableau()
    candidates: dict[str, str] = {}
    for label, key_material in KEY_MATERIAL.items():
        for offset in range(len(key_material)):
            dynamic_key = key_material[offset:] + key_material[:offset]
            candidates[f"{label} offset {offset} (Quagmire)"] = decrypt_quagmire_running(K4, dynamic_key, tableau)
            candidates[f"{label} offset {offset} (Vigenere)"] = decrypt_vigenere_standard(K4, dynamic_key)

    best_label, best_text = max(candidates.items(), key=lambda item: clue_overlap_score(item[1]))
    matched_label = next((label for label, text in candidates.items() if extract_clue_hits(text)), None)
    matched_clues = extract_clue_hits(candidates[matched_label]) if matched_label else []
    summary = (
        f"Matched {', '.join(matched_clues)} with {matched_label}."
        if matched_clues
        else "No running-key offset over K1-K3 or KRYPTOS produced the known K4 anchors."
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
        notes=["Evaluated every cyclic offset for the K1-K3 plaintexts and the KRYPTOS primer under Quagmire and Vigenere rules."],
        artifacts={"best_candidate": best_label},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
