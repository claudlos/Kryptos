"""Strategy 15 — Z340-Style Transposition Enumeration.

Systematically enumerates ALL plausible transposition patterns applied to the
K4 ciphertext, inverting each one and scoring the result with anchor/language
analysis.  The key insight from the Z340 solution: enumerate transposition
patterns in an outer loop, score with substitution/language analysis in an
inner loop.

Transposition families:
  1. Columnar transposition (all key lengths 2-32, exhaustive for width <= 8,
     keyword-seeded + random sampling for wider)
  2. Route cipher (spiral, snake/boustrophedon, diagonal, column-major)
  3. Rail fence (2-20 rails)
  4. Myszkowski transposition (keyword-derived with repeated letters)
  5. Double columnar (two sequential columnar transpositions)

Primary fast filter: check whether known plaintext anchors land at their
expected 0-indexed positions after the inverse transposition.  Most
transpositions fail immediately on the first anchor check.
"""

from __future__ import annotations

import itertools
import random
import time
from math import ceil
from typing import Any

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_ranked_candidate,
    build_score_breakdown,
    build_strategy_result,
    dedupe_ranked_candidates,
    sort_ranked_candidates,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    DEFAULT_KEYWORDS,
    K4,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import keyword_permutation, periodic_transposition_decrypt

SPEC = get_strategy_spec("15")

# ---------------------------------------------------------------------------
# Anchor positions (0-indexed) derived from the 1-indexed constants
# ---------------------------------------------------------------------------
_ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    _ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# Pre-compute the cheapest anchor check (EAST at 0-indexed 21-24)
_FAST_ANCHOR_TEXT = _ANCHORS[0][0]  # "EAST"
_FAST_ANCHOR_POS = _ANCHORS[0][1]   # 21

_CT_LEN = len(K4)  # 97


# ===================================================================
# Fast anchor filter
# ===================================================================

def _quick_anchor_pass(text: str, threshold: int = 2) -> bool:
    """Return True if at least *threshold* individual anchor chars match."""
    hits = 0
    for anchor_text, anchor_start in _ANCHORS:
        end = anchor_start + len(anchor_text)
        if end > len(text):
            continue
        for i, ch in enumerate(anchor_text):
            if text[anchor_start + i] == ch:
                hits += 1
                if hits >= threshold:
                    return True
    return False


def _full_anchor_char_matches(text: str) -> int:
    """Count how many individual anchor characters land at the right position."""
    hits = 0
    for anchor_text, anchor_start in _ANCHORS:
        end = anchor_start + len(anchor_text)
        if end > len(text):
            continue
        for i, ch in enumerate(anchor_text):
            if text[anchor_start + i] == ch:
                hits += 1
    return hits


# ===================================================================
# 1. Columnar transposition inverse
# ===================================================================

def _columnar_decrypt(ciphertext: str, perm: tuple[int, ...]) -> str:
    """Invert a columnar transposition defined by column-read permutation."""
    width = len(perm)
    n = len(ciphertext)
    nrows = ceil(n / width)
    # Number of columns that have 'nrows' entries (the rest have nrows-1)
    full_cols = n - (nrows - 1) * width  # columns with a full-length entry

    # Build index mapping: the encryption read columns in perm order
    col_lengths = []
    for col in perm:
        col_lengths.append(nrows if col < full_cols else nrows - 1)

    # Split ciphertext into columns (in perm order)
    columns: dict[int, list[str]] = {}
    pos = 0
    for col, clen in zip(perm, col_lengths):
        columns[col] = list(ciphertext[pos:pos + clen])
        pos += clen

    # Read back row by row
    result = []
    for row in range(nrows):
        for col in range(width):
            if col in columns and row < len(columns[col]):
                result.append(columns[col][row])
    return "".join(result)


def _enumerate_columnar(ciphertext: str, config: StrategyRuntimeConfig, candidates: list[dict[str, Any]], max_samples_per_width: int = 5000) -> int:
    """Enumerate columnar transposition inverses for widths 2-32."""
    attempts = 0
    rng = random.Random(42)

    for width in range(2, min(33, len(ciphertext))):
        if width <= 8:
            # Exhaustive enumeration is feasible: width! <= 40320
            perms = itertools.permutations(range(width))
        else:
            # For wider keys: use keyword-seeded permutations + random sampling
            perms_set: set[tuple[int, ...]] = set()
            # Keyword seeds
            for kw in DEFAULT_KEYWORDS:
                perms_set.add(keyword_permutation(kw, width))
            # Identity and reverse
            perms_set.add(tuple(range(width)))
            perms_set.add(tuple(reversed(range(width))))
            # Random samples
            base = list(range(width))
            while len(perms_set) < max_samples_per_width:
                rng.shuffle(base)
                perms_set.add(tuple(base))
            perms = iter(perms_set)

        for perm in perms:
            attempts += 1
            pt = _columnar_decrypt(ciphertext, perm)
            if _quick_anchor_pass(pt, threshold=2):
                char_hits = _full_anchor_char_matches(pt)
                if char_hits >= 3:
                    candidates.append(
                        build_ranked_candidate(
                            pt,
                            transform_chain=[f"columnar_inv:w{width}"],
                            corpus_bundle=config.corpora,
                            scorer_profile=config.scorer_profile,
                            key_material={
                                "family": "columnar",
                                "width": width,
                                "permutation": list(perm),
                                "anchor_char_hits": char_hits,
                            },
                            structure_hint=min(300, char_hits * 40),
                        )
                    )

    return attempts


# ===================================================================
# 2. Rail fence cipher inverse
# ===================================================================

def _rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    """Decrypt a rail-fence cipher with the given number of rails."""
    n = len(ciphertext)
    if rails <= 1 or rails >= n:
        return ciphertext

    # Build the zigzag pattern to determine character positions per rail
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for i in range(n):
        fence[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    # Assign ciphertext characters to their positions
    result = [''] * n
    pos = 0
    for rail_indices in fence:
        for idx in rail_indices:
            result[idx] = ciphertext[pos]
            pos += 1

    return "".join(result)


def _enumerate_rail_fence(ciphertext: str, config: StrategyRuntimeConfig, candidates: list[dict[str, Any]]) -> int:
    """Enumerate rail fence inverses for 2-20 rails."""
    attempts = 0
    for rails in range(2, 21):
        attempts += 1
        pt = _rail_fence_decrypt(ciphertext, rails)
        if _quick_anchor_pass(pt, threshold=2):
            char_hits = _full_anchor_char_matches(pt)
            if char_hits >= 3:
                candidates.append(
                    build_ranked_candidate(
                        pt,
                        transform_chain=[f"rail_fence_inv:r{rails}"],
                        corpus_bundle=config.corpora,
                        scorer_profile=config.scorer_profile,
                        key_material={
                            "family": "rail_fence",
                            "rails": rails,
                            "anchor_char_hits": char_hits,
                        },
                        structure_hint=min(300, char_hits * 40),
                    )
                )
    return attempts


# ===================================================================
# 3. Route cipher patterns
# ===================================================================

def _grid_dimensions(n: int) -> list[tuple[int, int]]:
    """Return (rows, cols) pairs where rows*cols >= n and rows*cols <= n+5."""
    dims = []
    for cols in range(2, n + 1):
        rows = ceil(n / cols)
        total = rows * cols
        if total >= n and total <= n + 5:
            dims.append((rows, cols))
    return dims


def _spiral_clockwise_inward(rows: int, cols: int, n: int) -> list[int]:
    """Generate indices for reading a grid in clockwise inward spiral order."""
    indices = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            idx = top * cols + c
            if idx < n:
                indices.append(idx)
        top += 1
        for r in range(top, bottom + 1):
            idx = r * cols + right
            if idx < n:
                indices.append(idx)
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                idx = bottom * cols + c
                if idx < n:
                    indices.append(idx)
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                idx = r * cols + left
                if idx < n:
                    indices.append(idx)
            left += 1
    return indices


def _spiral_counterclockwise_inward(rows: int, cols: int, n: int) -> list[int]:
    """Generate indices for reading a grid in counterclockwise inward spiral order."""
    indices = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for r in range(top, bottom + 1):
            idx = r * cols + left
            if idx < n:
                indices.append(idx)
        left += 1
        if top <= bottom:
            for c in range(left, right + 1):
                idx = bottom * cols + c
                if idx < n:
                    indices.append(idx)
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                idx = r * cols + right
                if idx < n:
                    indices.append(idx)
            right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                idx = top * cols + c
                if idx < n:
                    indices.append(idx)
            top += 1
    return indices


def _snake_boustrophedon(rows: int, cols: int, n: int) -> list[int]:
    """Read grid in boustrophedon (alternating row direction) order."""
    indices = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols):
                idx = r * cols + c
                if idx < n:
                    indices.append(idx)
        else:
            for c in range(cols - 1, -1, -1):
                idx = r * cols + c
                if idx < n:
                    indices.append(idx)
    return indices


def _column_major(rows: int, cols: int, n: int) -> list[int]:
    """Read grid column by column (top to bottom, left to right)."""
    indices = []
    for c in range(cols):
        for r in range(rows):
            idx = r * cols + c
            if idx < n:
                indices.append(idx)
    return indices


def _diagonal_reading(rows: int, cols: int, n: int) -> list[int]:
    """Read grid along diagonals (top-left to bottom-right)."""
    indices = []
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(rows, d + 1)):
            c = d - r
            idx = r * cols + c
            if idx < n:
                indices.append(idx)
    return indices


def _apply_route_inverse(ciphertext: str, read_indices: list[int]) -> str:
    """Apply the inverse of a route cipher: place ciphertext chars at read_indices, then read row-major."""
    n = len(ciphertext)
    # The encryption wrote plaintext chars to positions in read_indices order.
    # To decrypt: ciphertext[i] was read from position read_indices[i],
    # meaning plaintext[read_indices[i]] = ciphertext[i].
    # But we need to be careful about the direction of the inverse.
    #
    # If encryption reads positions in read_indices order to produce ciphertext,
    # then ciphertext[i] = plaintext[read_indices[i]].
    # So plaintext[read_indices[i]] = ciphertext[i].
    plaintext = ['?'] * n
    for ct_pos, pt_pos in enumerate(read_indices):
        if ct_pos < n and pt_pos < n:
            plaintext[pt_pos] = ciphertext[ct_pos]
    return "".join(ch for ch in plaintext if ch != '?')


def _apply_route_forward(ciphertext: str, read_indices: list[int]) -> str:
    """Apply route as a direct reordering: read ciphertext at the given indices."""
    n = len(ciphertext)
    result = []
    for idx in read_indices:
        if idx < n:
            result.append(ciphertext[idx])
    return "".join(result)


def _enumerate_route_ciphers(ciphertext: str, config: StrategyRuntimeConfig, candidates: list[dict[str, Any]]) -> int:
    """Enumerate route cipher patterns across viable grid dimensions."""
    attempts = 0
    n = len(ciphertext)
    dims = _grid_dimensions(n)

    route_generators = [
        ("spiral_cw_in", _spiral_clockwise_inward),
        ("spiral_ccw_in", _spiral_counterclockwise_inward),
        ("snake", _snake_boustrophedon),
        ("column_major", _column_major),
        ("diagonal", _diagonal_reading),
    ]

    for rows, cols in dims:
        for route_name, route_fn in route_generators:
            read_indices = route_fn(rows, cols, n)
            if len(read_indices) < n:
                continue

            # Try both directions of the inverse
            for direction, apply_fn in [("inverse", _apply_route_inverse), ("forward", _apply_route_forward)]:
                attempts += 1
                pt = apply_fn(ciphertext, read_indices)
                if len(pt) < n:
                    continue
                if _quick_anchor_pass(pt, threshold=2):
                    char_hits = _full_anchor_char_matches(pt)
                    if char_hits >= 3:
                        candidates.append(
                            build_ranked_candidate(
                                pt,
                                transform_chain=[f"route_{direction}:{route_name}:{rows}x{cols}"],
                                corpus_bundle=config.corpora,
                                scorer_profile=config.scorer_profile,
                                key_material={
                                    "family": "route_cipher",
                                    "route": route_name,
                                    "direction": direction,
                                    "rows": rows,
                                    "cols": cols,
                                    "anchor_char_hits": char_hits,
                                },
                                structure_hint=min(300, char_hits * 40),
                            )
                        )

    return attempts


# ===================================================================
# 4. Myszkowski transposition
# ===================================================================

def _myszkowski_decrypt(ciphertext: str, keyword: str) -> str:
    """Decrypt Myszkowski transposition using a keyword with possible repeated letters."""
    n = len(ciphertext)
    # Derive numeric key: rank letters, but equal letters share the same rank
    sorted_unique = sorted(set(keyword))
    rank_map = {ch: i for i, ch in enumerate(sorted_unique)}
    key_ranks = [rank_map[ch] for ch in keyword]
    width = len(keyword)
    nrows = ceil(n / width)

    # Group columns by rank
    rank_to_cols: dict[int, list[int]] = {}
    for col, rank in enumerate(key_ranks):
        rank_to_cols.setdefault(rank, []).append(col)

    # In Myszkowski, columns with the same rank are read off together
    # (interleaved row by row across those columns)
    result = [''] * n
    pos = 0
    for rank in sorted(rank_to_cols.keys()):
        cols = rank_to_cols[rank]
        for row in range(nrows):
            for col in cols:
                flat_idx = row * width + col
                if flat_idx < n and pos < n:
                    result[flat_idx] = ciphertext[pos]
                    pos += 1

    return "".join(result)


_MYSZKOWSKI_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
    "SANBORN", "SHADOW", "ILLUSION", "LANGLEY", "CIPHER",
    "EGYPT", "NILE", "GIZA", "TOMB", "CARTER",
    "BERLIN", "ALEXANDERPLATZ", "WORLD", "SECRET", "MESSAGE",
    "EAST", "NORTHEAST", "POSITION", "DELIVER",
]


def _enumerate_myszkowski(ciphertext: str, config: StrategyRuntimeConfig, candidates: list[dict[str, Any]]) -> int:
    """Enumerate Myszkowski transposition inverses using theme-relevant keywords."""
    attempts = 0
    seen_keys: set[tuple[int, ...]] = set()

    for keyword in _MYSZKOWSKI_KEYWORDS:
        if len(keyword) < 2 or len(keyword) > 32:
            continue
        # Derive key ranks
        sorted_unique = sorted(set(keyword))
        rank_map = {ch: i for i, ch in enumerate(sorted_unique)}
        key_ranks = tuple(rank_map[ch] for ch in keyword)

        if key_ranks in seen_keys:
            continue
        seen_keys.add(key_ranks)

        attempts += 1
        pt = _myszkowski_decrypt(ciphertext, keyword)
        if _quick_anchor_pass(pt, threshold=2):
            char_hits = _full_anchor_char_matches(pt)
            if char_hits >= 3:
                candidates.append(
                    build_ranked_candidate(
                        pt,
                        transform_chain=[f"myszkowski_inv:{keyword}"],
                        corpus_bundle=config.corpora,
                        scorer_profile=config.scorer_profile,
                        key_material={
                            "family": "myszkowski",
                            "keyword": keyword,
                            "key_ranks": list(key_ranks),
                            "anchor_char_hits": char_hits,
                        },
                        structure_hint=min(300, char_hits * 40),
                    )
                )

    return attempts


# ===================================================================
# 5. Double columnar transposition
# ===================================================================

def _enumerate_double_columnar(ciphertext: str, config: StrategyRuntimeConfig, candidates: list[dict[str, Any]], max_samples: int = 10000) -> int:
    """Enumerate double columnar transposition (two sequential columnar transpositions)."""
    attempts = 0
    rng = random.Random(137)

    # For practicality, use keyword-derived permutations for both layers
    keyword_perms: list[tuple[str, int, tuple[int, ...]]] = []
    for kw in DEFAULT_KEYWORDS:
        for width in range(3, 13):
            perm = keyword_permutation(kw, width)
            keyword_perms.append((kw, width, perm))
    # Add identity and reverse for small widths
    for width in range(3, 9):
        keyword_perms.append(("IDENTITY", width, tuple(range(width))))
        keyword_perms.append(("REVERSE", width, tuple(reversed(range(width)))))

    # Try all pairs of keyword-derived permutations (capped)
    pairs_tried = 0
    for i, (kw1, w1, p1) in enumerate(keyword_perms):
        for j, (kw2, w2, p2) in enumerate(keyword_perms):
            if pairs_tried >= max_samples:
                break
            pairs_tried += 1
            attempts += 1

            # Decrypt: undo second transposition, then first
            intermediate = _columnar_decrypt(ciphertext, p2)
            pt = _columnar_decrypt(intermediate, p1)

            if _quick_anchor_pass(pt, threshold=2):
                char_hits = _full_anchor_char_matches(pt)
                if char_hits >= 3:
                    candidates.append(
                        build_ranked_candidate(
                            pt,
                            transform_chain=[f"double_columnar_inv:{kw1}:w{w1}+{kw2}:w{w2}"],
                            corpus_bundle=config.corpora,
                            scorer_profile=config.scorer_profile,
                            key_material={
                                "family": "double_columnar",
                                "keyword_1": kw1,
                                "width_1": w1,
                                "permutation_1": list(p1),
                                "keyword_2": kw2,
                                "width_2": w2,
                                "permutation_2": list(p2),
                                "anchor_char_hits": char_hits,
                            },
                            structure_hint=min(300, char_hits * 40),
                        )
                    )
        if pairs_tried >= max_samples:
            break

    # Also try random permutation pairs for small widths
    for _ in range(min(max_samples - pairs_tried, 5000)):
        attempts += 1
        w1 = rng.randint(3, 10)
        w2 = rng.randint(3, 10)
        p1 = list(range(w1))
        rng.shuffle(p1)
        p2 = list(range(w2))
        rng.shuffle(p2)

        intermediate = _columnar_decrypt(ciphertext, tuple(p2))
        pt = _columnar_decrypt(intermediate, tuple(p1))

        if _quick_anchor_pass(pt, threshold=2):
            char_hits = _full_anchor_char_matches(pt)
            if char_hits >= 3:
                candidates.append(
                    build_ranked_candidate(
                        pt,
                        transform_chain=[f"double_columnar_inv:rand:w{w1}+w{w2}"],
                        corpus_bundle=config.corpora,
                        scorer_profile=config.scorer_profile,
                        key_material={
                            "family": "double_columnar",
                            "keyword_1": "RANDOM",
                            "width_1": w1,
                            "permutation_1": list(p1),
                            "keyword_2": "RANDOM",
                            "width_2": w2,
                            "permutation_2": list(p2),
                            "anchor_char_hits": char_hits,
                        },
                        structure_hint=min(300, char_hits * 40),
                    )
                )

    return attempts


# ===================================================================
# 6. Periodic transposition via existing infrastructure
# ===================================================================

def _enumerate_periodic(ciphertext: str, config: StrategyRuntimeConfig, candidates: list[dict[str, Any]]) -> int:
    """Use the existing periodic_transposition_decrypt for keyword-seeded permutations."""
    attempts = 0

    for width in range(2, min(33, len(ciphertext))):
        perms_to_try: list[tuple[str, tuple[int, ...]]] = []
        for kw in DEFAULT_KEYWORDS:
            perms_to_try.append((kw, keyword_permutation(kw, width)))
        perms_to_try.append(("IDENTITY", tuple(range(width))))
        perms_to_try.append(("REVERSE", tuple(reversed(range(width)))))

        for seed_name, perm in perms_to_try:
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                for rev_rows in (False, True):
                    for rev_cols in (False, True):
                        attempts += 1
                        pt = periodic_transposition_decrypt(
                            ciphertext,
                            width,
                            perm,
                            fill_mode=fill_mode,
                            read_mode=read_mode,
                            reverse_rows=rev_rows,
                            reverse_columns=rev_cols,
                        )
                        if _quick_anchor_pass(pt, threshold=2):
                            char_hits = _full_anchor_char_matches(pt)
                            if char_hits >= 3:
                                candidates.append(
                                    build_ranked_candidate(
                                        pt,
                                        transform_chain=[f"periodic_trans_inv:w{width}:{fill_mode}->{read_mode}:{seed_name}"],
                                        corpus_bundle=config.corpora,
                                        scorer_profile=config.scorer_profile,
                                        key_material={
                                            "family": "periodic_transposition",
                                            "keyword_seed": seed_name,
                                            "width": width,
                                            "permutation": list(perm),
                                            "fill_mode": fill_mode,
                                            "read_mode": read_mode,
                                            "reverse_rows": rev_rows,
                                            "reverse_columns": rev_cols,
                                            "anchor_char_hits": char_hits,
                                        },
                                        structure_hint=min(300, char_hits * 40),
                                    )
                                )

    return attempts


# ===================================================================
# Main entry point
# ===================================================================

def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    t0 = time.perf_counter()

    candidates: list[dict[str, Any]] = []
    total_attempts = 0

    # 1. Columnar transposition
    total_attempts += _enumerate_columnar(K4, config, candidates)

    # 2. Rail fence
    total_attempts += _enumerate_rail_fence(K4, config, candidates)

    # 3. Route ciphers (spiral, snake, diagonal, column-major)
    total_attempts += _enumerate_route_ciphers(K4, config, candidates)

    # 4. Myszkowski transposition
    total_attempts += _enumerate_myszkowski(K4, config, candidates)

    # 5. Double columnar
    total_attempts += _enumerate_double_columnar(K4, config, candidates)

    # 6. Periodic transposition (keyword-seeded via existing infrastructure)
    total_attempts += _enumerate_periodic(K4, config, candidates)

    elapsed = time.perf_counter() - t0

    # If no candidates survived the anchor filter, create a baseline from raw K4
    if not candidates:
        candidates.append(
            build_ranked_candidate(
                K4,
                transform_chain=["identity"],
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material={"family": "none", "note": "no transposition passed anchor filter"},
            )
        )

    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[: max(config.candidate_limit, 8)]

    families_searched = [
        "columnar (w2-32, exhaustive w<=8, sampled w>8)",
        "rail_fence (2-20 rails)",
        "route_cipher (spiral_cw, spiral_ccw, snake, column_major, diagonal)",
        "myszkowski (keyword-derived)",
        "double_columnar (keyword pairs + random)",
        "periodic_transposition (keyword-seeded)",
    ]

    result = build_strategy_result(
        SPEC,
        retained,
        attempts=total_attempts,
        notes=[
            f"Enumerated {total_attempts:,} transposition inverses across 6 families in {elapsed:.2f}s.",
            f"Families: {'; '.join(families_searched)}.",
            f"{len(candidates)} candidates survived the anchor position filter (>= 3 char matches).",
            "Primary filter: known-plaintext anchor characters at positions 21-24 (EAST), 25-33 (NORTHEAST), 63-68 (BERLIN), 69-73 (CLOCK).",
        ],
    )
    result.artifacts["candidate_count"] = len(ranked)
    result.artifacts["elapsed_seconds"] = round(elapsed, 4)
    result.artifacts["families_searched"] = families_searched
    return result
