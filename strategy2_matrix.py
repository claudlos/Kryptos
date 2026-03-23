from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import format_result, preview_text, score_substrings
from kryptos.constants import KNOWN_PLAINTEXT_CLUES, K4_PADDED
from kryptos.models import SearchMetrics, StrategyResult

SPEC = get_strategy_spec("2")
TARGET_CIPHERTEXTS = [details["ciphertext"] for details in KNOWN_PLAINTEXT_CLUES.values()]


def create_matrices() -> tuple[list[list[str]], list[list[str]]]:
    matrix_7x14 = [list(K4_PADDED[index:index + 14]) for index in range(0, 98, 14)]
    matrix_14x7 = [list(K4_PADDED[index:index + 7]) for index in range(0, 98, 7)]
    return matrix_7x14, matrix_14x7


def read_columns(matrix: list[list[str]]) -> str:
    return "".join(matrix[row][col] for col in range(len(matrix[0])) for row in range(len(matrix)))


def read_diagonals(matrix: list[list[str]]) -> str:
    rows = len(matrix)
    cols = len(matrix[0])
    result = []
    for diagonal in range(rows + cols - 1):
        for row in range(max(0, diagonal - cols + 1), min(rows, diagonal + 1)):
            col = diagonal - row
            result.append(matrix[row][col])
    return "".join(result)


def run() -> StrategyResult:
    matrix_7x14, matrix_14x7 = create_matrices()
    methods = {
        "7x14 columns": read_columns(matrix_7x14),
        "7x14 reverse columns": read_columns([row[::-1] for row in matrix_7x14]),
        "7x14 diagonals": read_diagonals(matrix_7x14),
        "14x7 columns": read_columns(matrix_14x7),
        "14x7 reverse columns": read_columns([row[::-1] for row in matrix_14x7]),
        "14x7 diagonals": read_diagonals(matrix_14x7),
    }
    best_name, best_text = max(
        methods.items(),
        key=lambda item: score_substrings(item[1].replace("?", ""), TARGET_CIPHERTEXTS),
    )
    matched = [target for target in TARGET_CIPHERTEXTS if target in best_text.replace("?", "")]
    summary = (
        f"Matched raw clue ciphertext via {best_name}."
        if matched
        else "No simple 7x14 or 14x7 read order reconstructed the clue ciphertext as a contiguous run."
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
        metrics=SearchMetrics(attempts=len(methods), unique_attempts=len(methods)),
        notes=["Tested padded 7x14 and 14x7 matrices with column and diagonal reads."],
        artifacts={"best_method": best_name},
    )


def main() -> None:
    print(format_result(run()))


if __name__ == "__main__":
    main()
