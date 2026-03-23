from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import format_result, preview_text, score_substrings
from kryptos.constants import KNOWN_PLAINTEXT_CLUES, K4_PADDED
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("5")
TARGET_CIPHERTEXTS = [details["ciphertext"] for details in KNOWN_PLAINTEXT_CLUES.values()]


def generate_masks(rows: int, cols: int) -> list[dict[str, object]]:
    masks = []
    for step in range(2, 8):
        masks.append({
            "name": f"Every {step}th character",
            "indices": [index for index in range(rows * cols) if index % step == 0],
        })
    for start_col in range(4):
        indices = []
        for row in range(rows):
            for col in range(start_col, cols, 2):
                indices.append(row * cols + col)
        masks.append({"name": f"Every 2nd column starting at {start_col}", "indices": indices})
    return masks


def apply_mask(text: str, indices: list[int]) -> str:
    return "".join(text[index] for index in indices if index < len(text))


def run() -> StrategyResult:
    masks = generate_masks(7, 14)
    outputs = {mask["name"]: apply_mask(K4_PADDED, mask["indices"]) for mask in masks}
    best_name, best_text = max(
        outputs.items(),
        key=lambda item: score_substrings(item[1].replace("?", ""), TARGET_CIPHERTEXTS),
    )
    matched = [target for target in TARGET_CIPHERTEXTS if target in best_text]
    summary = (
        f"Matched raw clue ciphertext with mask '{best_name}'."
        if matched
        else "No tested grille mask extracted the clue ciphertext as a continuous sequence."
    )
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status="match" if matched else "no_match",
        summary=summary,
        best_preview=preview_text(best_text.replace("?", "")),
        matched_clues=matched,
        metrics=SearchMetrics(attempts=len(outputs), unique_attempts=len(outputs)),
        notes=["Used simple modulus masks plus alternating-column masks over a padded 7x14 grid."],
        artifacts={"best_mask": best_name},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
