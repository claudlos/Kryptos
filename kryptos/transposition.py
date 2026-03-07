"""Periodic transposition helpers used by the K4 strategy pipeline."""

from __future__ import annotations

from math import ceil
from typing import Callable

from .constants import STANDARD_ALPHABET


def keyword_permutation(keyword: str, width: int) -> tuple[int, ...]:
    seed: list[str] = []
    for char in (keyword.upper() + STANDARD_ALPHABET):
        if char not in seed and char in STANDARD_ALPHABET:
            seed.append(char)
        if len(seed) == min(width, len(STANDARD_ALPHABET)):
            break
    sort_keys: list[str] = []
    for index in range(width):
        if index < len(seed):
            sort_keys.append(seed[index])
        else:
            sort_keys.append(f"{{{index:02d}}}")
    decorated = sorted(enumerate(sort_keys), key=lambda item: (item[1], item[0]))
    return tuple(index for index, _ in decorated)


def existing_cells(length: int, width: int) -> list[tuple[int, int]]:
    rows = ceil(length / width)
    cells: list[tuple[int, int]] = []
    for row in range(rows):
        row_width = width if row < rows - 1 or length % width == 0 else length % width
        for column in range(row_width):
            cells.append((row, column))
    return cells


def row_order(cells: set[tuple[int, int]], reverse_rows: bool) -> list[tuple[int, int]]:
    rows = sorted({row for row, _ in cells})
    ordered: list[tuple[int, int]] = []
    for row in rows:
        columns = sorted(column for cell_row, column in cells if cell_row == row)
        if reverse_rows:
            columns.reverse()
        ordered.extend((row, column) for column in columns)
    return ordered


def column_order(cells: set[tuple[int, int]], permutation: tuple[int, ...], reverse_columns: bool) -> list[tuple[int, int]]:
    ordered: list[tuple[int, int]] = []
    for column in permutation:
        rows = sorted(row for row, cell_column in cells if cell_column == column)
        if reverse_columns:
            rows.reverse()
        ordered.extend((row, column) for row in rows)
    return ordered


def fill_order(cells: set[tuple[int, int]], fill_mode: str, reverse_rows: bool, reverse_columns: bool) -> list[tuple[int, int]]:
    if fill_mode == "row":
        return row_order(cells, reverse_rows)
    if fill_mode == "column":
        return column_order(cells, tuple(sorted({column for _, column in cells})), reverse_columns)
    raise ValueError(f"Unsupported fill_mode: {fill_mode}")


def read_order(
    cells: set[tuple[int, int]],
    read_mode: str,
    permutation: tuple[int, ...],
    reverse_rows: bool,
    reverse_columns: bool,
) -> list[tuple[int, int]]:
    if read_mode == "row":
        return row_order(cells, reverse_rows)
    if read_mode == "column":
        return column_order(cells, permutation, reverse_columns)
    raise ValueError(f"Unsupported read_mode: {read_mode}")


def periodic_transposition_encrypt(
    plaintext: str,
    width: int,
    permutation: tuple[int, ...],
    *,
    fill_mode: str = "row",
    read_mode: str = "column",
    reverse_rows: bool = False,
    reverse_columns: bool = False,
) -> str:
    cells = set(existing_cells(len(plaintext), width))
    fill_cells = fill_order(cells, fill_mode, reverse_rows, reverse_columns)
    read_cells = read_order(cells, read_mode, permutation, reverse_rows, reverse_columns)
    grid = {cell: char for cell, char in zip(fill_cells, plaintext)}
    return "".join(grid[cell] for cell in read_cells)


def periodic_transposition_decrypt(
    ciphertext: str,
    width: int,
    permutation: tuple[int, ...],
    *,
    fill_mode: str = "row",
    read_mode: str = "column",
    reverse_rows: bool = False,
    reverse_columns: bool = False,
) -> str:
    cells = set(existing_cells(len(ciphertext), width))
    fill_cells = fill_order(cells, fill_mode, reverse_rows, reverse_columns)
    read_cells = read_order(cells, read_mode, permutation, reverse_rows, reverse_columns)
    grid = {cell: char for cell, char in zip(read_cells, ciphertext)}
    return "".join(grid[cell] for cell in fill_cells)


def identity_permutation(width: int) -> tuple[int, ...]:
    return tuple(range(width))


def hillclimb_permutation(
    ciphertext: str,
    width: int,
    seed_permutation: tuple[int, ...],
    scorer: Callable[[str], tuple[int, dict[str, int]]],
    *,
    fill_mode: str,
    read_mode: str,
    reverse_rows: bool,
    reverse_columns: bool,
    max_rounds: int = 2,
) -> dict[str, object]:
    current = seed_permutation
    current_plaintext = periodic_transposition_decrypt(
        ciphertext,
        width,
        current,
        fill_mode=fill_mode,
        read_mode=read_mode,
        reverse_rows=reverse_rows,
        reverse_columns=reverse_columns,
    )
    current_score, current_breakdown = scorer(current_plaintext)
    for _ in range(max_rounds):
        improved = False
        for left in range(width - 1):
            for right in {left + 1, width - 1 - left}:
                if right <= left or right >= width:
                    continue
                swapped = list(current)
                swapped[left], swapped[right] = swapped[right], swapped[left]
                candidate = tuple(swapped)
                plaintext = periodic_transposition_decrypt(
                    ciphertext,
                    width,
                    candidate,
                    fill_mode=fill_mode,
                    read_mode=read_mode,
                    reverse_rows=reverse_rows,
                    reverse_columns=reverse_columns,
                )
                score, breakdown = scorer(plaintext)
                if score > current_score:
                    current = candidate
                    current_plaintext = plaintext
                    current_score = score
                    current_breakdown = breakdown
                    improved = True
        if not improved:
            break
    return {
        "plaintext": current_plaintext,
        "score": current_score,
        "breakdown": current_breakdown,
        "permutation": current,
        "width": width,
        "fill_mode": fill_mode,
        "read_mode": read_mode,
        "reverse_rows": reverse_rows,
        "reverse_columns": reverse_columns,
    }