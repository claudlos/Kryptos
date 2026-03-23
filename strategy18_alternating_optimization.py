"""Lasry-style alternating optimization for compound ciphers on K4.

Jointly optimizes substitution (Vigenère) + transposition (columnar) layers:
  1. Initialize with random/keyword-seeded transposition key
  2. Fix transposition, optimize substitution via hill climbing
  3. Fix substitution, optimize transposition via hill climbing
  4. Repeat until convergence
  5. Nested random restarts: restart outer loop N times, keep best
"""

from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    anchor_alignment_score,
    build_ranked_candidate,
    build_score_breakdown,
    build_strategy_result,
    decrypt_vigenere_standard,
    dedupe_ranked_candidates,
    language_shape_score,
    normalize_letters,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    DEFAULT_KEYWORDS,
    K4,
    KNOWN_PLAINTEXT_CLUES,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import (
    identity_permutation,
    keyword_permutation,
    periodic_transposition_decrypt,
)

import math
import random

SPEC = get_strategy_spec("18")

# ---------------------------------------------------------------------------
# Known plaintext anchors (0-indexed positions)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

COMBINED_ANCHORS: list[tuple[str, int]] = []
for _clue, _details in KNOWN_PLAINTEXT_CLUES.items():
    COMBINED_ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# Periods to try for Vigenère substitution layer
VIGENERE_PERIODS = (5, 6, 7, 8, 10, 12, 14)

# Iteration budget
NUM_RESTARTS = 3           # outer random restarts
MAX_ALT_ROUNDS = 4         # alternating rounds per restart
VIG_HILLCLIMB_ITERS = 40   # per-position hill-climb iterations for Vigenère key
TRANS_HILLCLIMB_SWAPS = 30 # swap attempts for transposition permutation


def _combined_score(text: str) -> int:
    """Lightweight score combining anchor alignment and language shape."""
    return anchor_alignment_score(text) + language_shape_score(text)


def _derive_vigenere_key_from_anchors(ciphertext: str, period: int) -> list[int]:
    """Use known plaintext anchors to constrain Vigenère key positions.

    Returns a list of length `period` with shift values (0-25).
    Positions not constrained by anchors are initialized to 0.
    """
    shifts: list[int | None] = [None] * period
    for plaintext, start_idx in ANCHORS:
        for offset, (p_char, c_char) in enumerate(
            zip(plaintext, ciphertext[start_idx : start_idx + len(plaintext)])
        ):
            slot = (start_idx + offset) % period
            derived = (STANDARD_ALPHABET.index(c_char) - STANDARD_ALPHABET.index(p_char)) % 26
            if shifts[slot] is None:
                shifts[slot] = derived
            elif shifts[slot] != derived:
                # Contradiction — this period is inconsistent with anchors
                return []
    return [s if s is not None else 0 for s in shifts]


def _shifts_to_key_string(shifts: list[int]) -> str:
    return "".join(STANDARD_ALPHABET[s] for s in shifts)


def _random_permutation(width: int, rng: random.Random) -> tuple[int, ...]:
    perm = list(range(width))
    rng.shuffle(perm)
    return tuple(perm)


def _swap_permutation(perm: tuple[int, ...], rng: random.Random) -> tuple[int, ...]:
    """Apply a single random adjacent-or-distant swap to a permutation."""
    w = len(perm)
    if w < 2:
        return perm
    lst = list(perm)
    i = rng.randrange(w)
    j = rng.randrange(w)
    while j == i:
        j = rng.randrange(w)
    lst[i], lst[j] = lst[j], lst[i]
    return tuple(lst)


def _hillclimb_vigenere_key(
    ciphertext: str,
    initial_shifts: list[int],
    fixed_slots: set[int],
    rng: random.Random,
    max_iters: int = VIG_HILLCLIMB_ITERS,
) -> tuple[list[int], int]:
    """Hill-climb Vigenère key shifts on free (non-anchor-constrained) positions."""
    best_shifts = list(initial_shifts)
    best_text = decrypt_vigenere_standard(ciphertext, _shifts_to_key_string(best_shifts))
    best_score = _combined_score(best_text)

    period = len(best_shifts)
    free_slots = [i for i in range(period) if i not in fixed_slots]

    for _ in range(max_iters):
        if not free_slots:
            break
        slot = rng.choice(free_slots)
        old_val = best_shifts[slot]
        new_val = rng.randrange(26)
        if new_val == old_val:
            continue
        candidate_shifts = list(best_shifts)
        candidate_shifts[slot] = new_val
        text = decrypt_vigenere_standard(ciphertext, _shifts_to_key_string(candidate_shifts))
        score = _combined_score(text)
        if score > best_score:
            best_shifts = candidate_shifts
            best_score = score

    return best_shifts, best_score


def _hillclimb_transposition(
    ciphertext: str,
    width: int,
    initial_perm: tuple[int, ...],
    rng: random.Random,
    fill_mode: str = "row",
    read_mode: str = "column",
    max_swaps: int = TRANS_HILLCLIMB_SWAPS,
) -> tuple[tuple[int, ...], str, int]:
    """Hill-climb column permutation for transposition layer."""
    best_perm = initial_perm
    best_text = periodic_transposition_decrypt(
        ciphertext, width, best_perm, fill_mode=fill_mode, read_mode=read_mode
    )
    best_score = _combined_score(best_text)

    for _ in range(max_swaps):
        candidate_perm = _swap_permutation(best_perm, rng)
        text = periodic_transposition_decrypt(
            ciphertext, width, candidate_perm, fill_mode=fill_mode, read_mode=read_mode
        )
        score = _combined_score(text)
        if score > best_score:
            best_perm = candidate_perm
            best_text = text
            best_score = score

    return best_perm, best_text, best_score


def _alternating_optimization(
    ciphertext: str,
    period: int,
    width: int,
    initial_perm: tuple[int, ...],
    rng: random.Random,
    fill_mode: str = "row",
    read_mode: str = "column",
) -> dict[str, object]:
    """Run alternating optimization for one (period, width, initial_perm) configuration."""

    # Derive anchor-constrained Vigenère key
    anchor_shifts = _derive_vigenere_key_from_anchors(ciphertext, period)
    if not anchor_shifts:
        # Period incompatible with anchors; use random key
        anchor_shifts = [rng.randrange(26) for _ in range(period)]
        fixed_slots: set[int] = set()
    else:
        fixed_slots = set()
        for plaintext, start_idx in ANCHORS:
            for offset in range(len(plaintext)):
                slot = (start_idx + offset) % period
                fixed_slots.add(slot)

    current_shifts = list(anchor_shifts)
    current_perm = initial_perm
    best_score = -1
    best_text = ""
    best_key = ""
    best_perm = current_perm

    for _round in range(MAX_ALT_ROUNDS):
        # Phase 1: fix transposition, optimize Vigenère key
        # First apply transposition to get intermediate text
        transposed = periodic_transposition_decrypt(
            ciphertext, width, current_perm, fill_mode=fill_mode, read_mode=read_mode
        )
        current_shifts, score_after_vig = _hillclimb_vigenere_key(
            transposed, current_shifts, fixed_slots, rng
        )
        key_str = _shifts_to_key_string(current_shifts)
        vig_text = decrypt_vigenere_standard(transposed, key_str)

        # Phase 2: fix Vigenère key, optimize transposition
        # We need to find a transposition such that
        # decrypt_vig(decrypt_trans(ct, perm), key) is maximized
        # Hill-climb on permutation, scoring the full pipeline
        trial_perm = current_perm
        trial_score = _combined_score(vig_text)

        for _ in range(TRANS_HILLCLIMB_SWAPS):
            cand_perm = _swap_permutation(trial_perm, rng)
            cand_transposed = periodic_transposition_decrypt(
                ciphertext, width, cand_perm, fill_mode=fill_mode, read_mode=read_mode
            )
            cand_text = decrypt_vigenere_standard(cand_transposed, key_str)
            cand_score = _combined_score(cand_text)
            if cand_score > trial_score:
                trial_perm = cand_perm
                trial_score = cand_score
                vig_text = cand_text

        current_perm = trial_perm

        if trial_score > best_score:
            best_score = trial_score
            best_text = vig_text
            best_key = key_str
            best_perm = current_perm
        elif trial_score == best_score:
            # Converged
            break

    return {
        "text": best_text,
        "score": best_score,
        "vigenere_key": best_key,
        "period": period,
        "width": width,
        "permutation": best_perm,
        "fill_mode": fill_mode,
        "read_mode": read_mode,
    }


def _also_try_vig_only(
    ciphertext: str,
    period: int,
    rng: random.Random,
) -> dict[str, object]:
    """Try Vigenère-only (no transposition) as a degenerate case."""
    anchor_shifts = _derive_vigenere_key_from_anchors(ciphertext, period)
    if not anchor_shifts:
        anchor_shifts = [rng.randrange(26) for _ in range(period)]
        fixed_slots: set[int] = set()
    else:
        fixed_slots = set()
        for plaintext, start_idx in ANCHORS:
            for offset in range(len(plaintext)):
                slot = (start_idx + offset) % period
                fixed_slots.add(slot)

    best_shifts, best_score = _hillclimb_vigenere_key(
        ciphertext, anchor_shifts, fixed_slots, rng, max_iters=VIG_HILLCLIMB_ITERS * 2
    )
    key_str = _shifts_to_key_string(best_shifts)
    text = decrypt_vigenere_standard(ciphertext, key_str)
    return {
        "text": text,
        "score": best_score,
        "vigenere_key": key_str,
        "period": period,
        "width": 0,
        "permutation": (),
        "fill_mode": "none",
        "read_mode": "none",
    }


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    rng = random.Random(20250321)
    attempts = 0
    all_results: list[dict[str, object]] = []

    # Transposition widths to try
    widths = [w for w in (7, 9, 10, 12, 14) if w < len(K4)]

    # Keyword seeds for initial permutations
    kw_seeds = list(DEFAULT_KEYWORDS[:3]) + ["IDENTITY"]

    for period in VIGENERE_PERIODS:
        # Vigenère-only attempts (no transposition)
        for _restart in range(2):
            result = _also_try_vig_only(K4, period, rng)
            attempts += 1
            all_results.append(result)

        # Combined Vigenère + transposition
        for width in widths:
            for fill_mode, read_mode in (("row", "column"),):
                for kw in kw_seeds:
                    for _restart in range(NUM_RESTARTS):
                        attempts += 1
                        if kw == "IDENTITY":
                            init_perm = identity_permutation(width)
                        else:
                            init_perm = keyword_permutation(kw, width)
                        # Perturb the seed permutation for diversity on restarts
                        if _restart > 0:
                            for _ in range(rng.randint(1, width)):
                                init_perm = _swap_permutation(init_perm, rng)

                        result = _alternating_optimization(
                            K4, period, width, init_perm, rng,
                            fill_mode=fill_mode, read_mode=read_mode,
                        )
                        all_results.append(result)

    # Build ranked candidates from all results
    candidates: list[dict[str, object]] = []
    for r in all_results:
        text = str(r["text"])
        if not text:
            continue
        chain = []
        if r["width"]:
            chain.append(
                f"periodic_transposition:w{r['width']}:{r['fill_mode']}->{r['read_mode']}"
            )
        chain.append(f"vigenere:period={r['period']}:key={r['vigenere_key']}")

        candidates.append(
            build_ranked_candidate(
                text,
                transform_chain=chain,
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material={
                    "vigenere_key": r["vigenere_key"],
                    "period": r["period"],
                    "width": r["width"],
                    "permutation": list(r["permutation"]) if r["permutation"] else [],
                    "fill_mode": r["fill_mode"],
                    "read_mode": r["read_mode"],
                },
            )
        )

    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[: max(config.candidate_limit, 8)]

    return build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=[
            f"Alternating optimization across {len(VIGENERE_PERIODS)} Vigenère periods × {len(widths)} transposition widths.",
            f"Used {NUM_RESTARTS} random restarts per config, {MAX_ALT_ROUNDS} alternating rounds each.",
            f"Known plaintext anchors used to constrain Vigenère key where period is consistent.",
            f"Total configurations evaluated: {attempts}.",
        ],
    )
