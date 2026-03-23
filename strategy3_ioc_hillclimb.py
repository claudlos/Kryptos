from __future__ import annotations

import math
import random

from kryptos.catalog import get_strategy_spec
from kryptos.common import calculate_ioc, chunked_ioc, extract_clue_hits, format_result, preview_text, score_substrings
from kryptos.constants import KNOWN_PLAINTEXT_CLUES, K4
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("3")
PLAINTEXT_TARGETS = list(KNOWN_PLAINTEXT_CLUES)
CIPHERTEXT_TARGETS = [details["ciphertext"] for details in KNOWN_PLAINTEXT_CLUES.values()]


def apply_columnar_transposition(text: str, col_order: list[int]) -> str:
    width = len(col_order)
    padded_len = math.ceil(len(text) / width) * width
    padded_text = text.ljust(padded_len, "X")
    grid = [padded_text[index:index + width] for index in range(0, padded_len, width)]
    return "".join(row[col_index] for col_index in col_order for row in grid)


def fitness(text: str) -> int:
    clue_score = score_substrings(text, PLAINTEXT_TARGETS, full_match_weight=1_000_000)
    cipher_score = score_substrings(text, CIPHERTEXT_TARGETS, full_match_weight=10_000)
    ioc_score = int(chunked_ioc(text, width=12) * 100_000)
    return clue_score + cipher_score + ioc_score


def hill_climb_transposition(width: int, iterations: int = 5_000, restarts: int = 5, seed: int = 17) -> dict[str, object]:
    rng = random.Random(seed + width)
    best_order = list(range(width))
    best_text = apply_columnar_transposition(K4, best_order)
    best_score = fitness(best_text)
    attempts = 1

    for _ in range(restarts):
        current_order = list(range(width))
        rng.shuffle(current_order)
        current_text = apply_columnar_transposition(K4, current_order)
        current_score = fitness(current_text)
        attempts += 1

        for _ in range(iterations):
            new_order = current_order.copy()
            idx1, idx2 = rng.sample(range(width), 2)
            new_order[idx1], new_order[idx2] = new_order[idx2], new_order[idx1]
            new_text = apply_columnar_transposition(K4, new_order)
            new_score = fitness(new_text)
            attempts += 1
            if new_score > current_score:
                current_order = new_order
                current_text = new_text
                current_score = new_score

        if current_score > best_score:
            best_order = current_order
            best_text = current_text
            best_score = current_score

    return {
        "width": width,
        "order": best_order,
        "text": best_text,
        "score": best_score,
        "local_ioc": chunked_ioc(best_text, width=12),
        "attempts": attempts,
    }


def run() -> StrategyResult:
    widths = [7, 8, 14, 21, 24, 28]
    candidates = [hill_climb_transposition(width) for width in widths]
    best_candidate = max(candidates, key=lambda candidate: int(candidate["score"]))
    best_text = str(best_candidate["text"])
    matched_clues = extract_clue_hits(best_text)
    summary = (
        f"Matched {', '.join(matched_clues)} at width {best_candidate['width']}."
        if matched_clues
        else (
            "No known anchors surfaced; the best candidate came from width "
            f"{best_candidate['width']} with local IoC {float(best_candidate['local_ioc']):.4f}."
        )
    )
    total_attempts = sum(int(candidate["attempts"]) for candidate in candidates)
    return StrategyResult(
        strategy_id=SPEC["id"],
        name=SPEC["name"],
        objective=SPEC["objective"],
        hypothesis=SPEC["hypothesis"],
        status="match" if matched_clues else "no_match",
        summary=summary,
        best_preview=preview_text(best_text),
        matched_clues=matched_clues,
        metrics=SearchMetrics(attempts=total_attempts, unique_attempts=total_attempts),
        notes=[
            f"Original ciphertext IoC: {calculate_ioc(K4):.4f}.",
            "Fitness combines clue overlap with chunked IoC so the objective matches the documented heuristic.",
        ],
        artifacts={
            "best_width": int(best_candidate["width"]),
            "best_order": list(best_candidate["order"]),
            "best_score": int(best_candidate["score"]),
            "best_local_ioc": round(float(best_candidate["local_ioc"]), 6),
        },
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
