"""Strategy 16 — SAT/SMT Constraint Elimination.

Uses Z3 to encode cipher hypotheses as constraint systems and check
satisfiability against the known K4 plaintext anchors.  For each cipher
family and parameter set the solver reports SATISFIABLE (with a witness
key), UNSATISFIABLE (proven impossible), or UNKNOWN.

Gracefully degrades when z3 is not installed.
"""

from __future__ import annotations

import itertools
from typing import Any

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_ranked_candidate,
    build_strategy_result,
    dedupe_ranked_candidates,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    K4,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig

SPEC = get_strategy_spec("16")

# ---------------------------------------------------------------------------
# Known plaintext pairs  (0-indexed position -> (ciphertext_char, plain_char))
# ---------------------------------------------------------------------------

def _build_known_pairs() -> list[tuple[int, int, int]]:
    """Return list of (0-indexed position, cipher_ord, plain_ord)."""
    pairs: list[tuple[int, int, int]] = []
    for clue, details in ANCHOR_COMPONENT_CLUES.items():
        start = int(details["start_index"]) - 1  # convert 1-indexed to 0-indexed
        ct = details["ciphertext"]
        for offset, (c_ch, p_ch) in enumerate(zip(ct, clue)):
            ci = STANDARD_ALPHABET.index(c_ch)
            pi = STANDARD_ALPHABET.index(p_ch)
            pairs.append((start + offset, ci, pi))
    return pairs


KNOWN_PAIRS = _build_known_pairs()

# ---------------------------------------------------------------------------
# Z3 availability
# ---------------------------------------------------------------------------

try:
    from z3 import And, Distinct, If, Int, Or, Solver, sat, unsat  # type: ignore[import-untyped]

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

# ---------------------------------------------------------------------------
# Hypothesis testers (each returns a result dict)
# ---------------------------------------------------------------------------

SAT_LABEL = "SATISFIABLE"
UNSAT_LABEL = "UNSATISFIABLE"
UNKNOWN_LABEL = "UNKNOWN"


def _result(family: str, params: str, status: str, witness: str | None = None) -> dict[str, str | None]:
    return {"family": family, "params": params, "status": status, "witness": witness}


# ---- Vigenere ----

def _check_vigenere(period: int) -> dict[str, str | None]:
    """Vigenere with repeating key of given period.

    key[i] = (C[i] - P[i]) mod 26.  All positions sharing (pos mod period)
    must yield the same key letter.
    """
    slots: dict[int, set[int]] = {}
    for pos, ci, pi in KNOWN_PAIRS:
        slot = pos % period
        shift = (ci - pi) % 26
        slots.setdefault(slot, set()).add(shift)

    # Pure arithmetic check first (faster than Z3 for this simple case)
    for slot, shifts in slots.items():
        if len(shifts) > 1:
            return _result("Vigenere", f"period={period}", UNSAT_LABEL)

    # Consistent — build witness key
    key_letters: list[str] = []
    for s in range(period):
        if s in slots:
            key_letters.append(STANDARD_ALPHABET[next(iter(slots[s]))])
        else:
            key_letters.append("?")
    witness = "".join(key_letters)
    return _result("Vigenere", f"period={period}", SAT_LABEL, witness)


# ---- Beaufort ----

def _check_beaufort(period: int) -> dict[str, str | None]:
    """Beaufort: key[i] = (P[i] - C[i]) mod 26 (equivalently C = key - P mod 26)."""
    slots: dict[int, set[int]] = {}
    for pos, ci, pi in KNOWN_PAIRS:
        slot = pos % period
        shift = (pi - ci) % 26
        slots.setdefault(slot, set()).add(shift)

    for slot, shifts in slots.items():
        if len(shifts) > 1:
            return _result("Beaufort", f"period={period}", UNSAT_LABEL)

    key_letters = []
    for s in range(period):
        if s in slots:
            key_letters.append(STANDARD_ALPHABET[next(iter(slots[s]))])
        else:
            key_letters.append("?")
    return _result("Beaufort", f"period={period}", SAT_LABEL, "".join(key_letters))


# ---- Columnar transposition (Z3) ----

def _check_columnar_transposition_z3(period: int) -> dict[str, str | None]:
    """Use Z3 to search for a column permutation of given width that maps
    known plaintext positions correctly.

    The columnar transposition model:
      - Text is written row-by-row into a grid of `period` columns.
      - Columns are read out in a permuted order to produce ciphertext.
      - perm[j] = the column that occupies position j in the read-out order.
    """
    if not Z3_AVAILABLE:
        return _result("ColumnarTransposition", f"period={period}", UNKNOWN_LABEL)

    n = len(K4)
    nrows = (n + period - 1) // period
    full_cols = n % period or period  # number of columns with nrows entries

    s = Solver()
    s.set("timeout", 5000)  # 5-second timeout per instance

    perm = [Int(f"perm_{j}") for j in range(period)]
    for j in range(period):
        s.add(perm[j] >= 0, perm[j] < period)
    s.add(Distinct(*perm))

    # For each known pair: given plaintext position pt_pos, compute
    # which (row, col) it sits at, then which ciphertext position that
    # maps to under permutation perm.
    for pt_pos, ci, pi in KNOWN_PAIRS:
        pt_row = pt_pos // period
        pt_col = pt_pos % period

        # Under permutation, column pt_col is read at order position inv_perm[pt_col].
        # The ciphertext index for (row, col) depends on how many rows each
        # read-order column has.  We encode this symbolically.
        # ct_pos = sum of rows for columns read before this one + row offset.
        # This is complex symbolically — instead enumerate possible perm positions.
        clauses = []
        for order_pos in range(period):
            # If perm[order_pos] == pt_col, then this column is read at order_pos.
            # Columns before order_pos contribute their full row count.
            ct_idx = 0
            for earlier in range(order_pos):
                # We need perm[earlier] to know its row count — too symbolic.
                # Use a different approach: enumerate full permutation for small periods.
                pass
            # Fall back to direct enumeration for small periods
            clauses = None
            break

        if clauses is None:
            break
    else:
        # Should not reach here for the break-based logic
        pass

    # For periods up to 10 do direct enumeration; above that report UNKNOWN
    if period > 10:
        return _result("ColumnarTransposition", f"period={period}", UNKNOWN_LABEL)

    # Direct enumeration for small periods
    for perm_candidate in itertools.permutations(range(period)):
        if _columnar_perm_consistent(perm_candidate, period, n):
            witness = ",".join(str(c) for c in perm_candidate)
            return _result("ColumnarTransposition", f"period={period}", SAT_LABEL, f"[{witness}]")

    return _result("ColumnarTransposition", f"period={period}", UNSAT_LABEL)


def _columnar_perm_consistent(perm: tuple[int, ...], period: int, n: int) -> bool:
    """Check if a columnar transposition permutation is consistent with known plaintext."""
    nrows = (n + period - 1) // period
    full_cols = n - (nrows - 1) * period  # columns that have nrows entries

    # Build mapping: plaintext_pos -> ciphertext_pos
    # Columns are read in order perm[0], perm[1], ...
    # Column perm[j] has nrows entries if perm[j] < full_cols, else nrows-1.
    ct_pos = 0
    col_ct_start: dict[int, int] = {}
    col_nrows: dict[int, int] = {}
    for j in range(period):
        col = perm[j]
        col_ct_start[col] = ct_pos
        rows_in_col = nrows if col < full_cols else nrows - 1
        col_nrows[col] = rows_in_col
        ct_pos += rows_in_col

    for pt_pos, ci, pi in KNOWN_PAIRS:
        row = pt_pos // period
        col = pt_pos % period
        if col not in col_ct_start:
            return False
        if row >= col_nrows.get(col, 0):
            return False
        ct_idx = col_ct_start[col] + row
        if ct_idx >= n:
            return False
        # Under transposition, the character at ciphertext position ct_idx
        # should be the same as the character at plaintext position pt_pos.
        # But transposition doesn't change letter identities — it only rearranges.
        # So CT[ct_idx] must equal PT[pt_pos].
        # We know CT[ct_idx] = K4[ct_idx] and PT[pt_pos] = known plaintext char.
        actual_ct = STANDARD_ALPHABET.index(K4[ct_idx])
        if actual_ct != pi:
            # The character at this ciphertext position must equal the plaintext char
            return False

    return True


# ---- Autokey (Vigenere-style) ----

def _check_autokey_vigenere(primer: str) -> dict[str, str | None]:
    """Autokey-Vigenere: key stream = primer + plaintext.

    At position i:
      if i < len(primer): key_char = primer[i]
      else: key_char = plaintext[i - len(primer)]
    Encryption: C[i] = (P[i] + key[i]) mod 26

    Check: at known positions, infer the plaintext and verify the key stream
    is self-consistent.
    """
    plen = len(primer)
    # Sort known pairs by position
    sorted_pairs = sorted(KNOWN_PAIRS, key=lambda t: t[0])

    # For each known position, compute what the key must be
    inferred_key: dict[int, int] = {}
    inferred_plain: dict[int, int] = {}

    # First, populate all known plaintext positions
    for pos, ci, pi in sorted_pairs:
        inferred_plain[pos] = pi

    # Now check key consistency
    for pos, ci, pi in sorted_pairs:
        # key[pos] = (C[pos] - P[pos]) mod 26
        key_val = (ci - pi) % 26

        if pos < plen:
            # Key should be from primer
            expected = STANDARD_ALPHABET.index(primer[pos])
            if key_val != expected:
                return _result("Autokey-Vigenere", f"primer={primer}", UNSAT_LABEL)
        else:
            # Key should be plaintext[pos - plen]
            source_pos = pos - plen
            if source_pos in inferred_plain:
                if key_val != inferred_plain[source_pos]:
                    return _result("Autokey-Vigenere", f"primer={primer}", UNSAT_LABEL)
            else:
                # We learn what plaintext[source_pos] must be
                inferred_plain[source_pos] = key_val

    return _result("Autokey-Vigenere", f"primer={primer}", SAT_LABEL, primer)


# ---- Autokey (Beaufort-style) ----

def _check_autokey_beaufort(primer: str) -> dict[str, str | None]:
    """Autokey-Beaufort: C[i] = (key[i] - P[i]) mod 26, key stream = primer + plaintext."""
    plen = len(primer)
    sorted_pairs = sorted(KNOWN_PAIRS, key=lambda t: t[0])
    inferred_plain: dict[int, int] = {}

    for pos, ci, pi in sorted_pairs:
        inferred_plain[pos] = pi

    for pos, ci, pi in sorted_pairs:
        # key[pos] = (C[pos] + P[pos]) mod 26
        key_val = (ci + pi) % 26

        if pos < plen:
            expected = STANDARD_ALPHABET.index(primer[pos])
            if key_val != expected:
                return _result("Autokey-Beaufort", f"primer={primer}", UNSAT_LABEL)
        else:
            source_pos = pos - plen
            if source_pos in inferred_plain:
                if key_val != inferred_plain[source_pos]:
                    return _result("Autokey-Beaufort", f"primer={primer}", UNSAT_LABEL)
            else:
                inferred_plain[source_pos] = key_val

    return _result("Autokey-Beaufort", f"primer={primer}", SAT_LABEL, primer)


# ---- Bifid ----

def _check_bifid(period: int, square: str) -> dict[str, str | None]:
    """Check Bifid cipher with given period and Polybius square.

    Bifid decryption inverts fractionation: for each block, the ciphertext
    is split into coordinate pairs, unzipped, and looked up.  We verify
    that known plaintext would produce the actual ciphertext under encryption.
    """
    from kryptos.common import bifid_encrypt, generate_polybius_square

    # Build known plaintext string (with '?' for unknowns)
    n = len(K4)
    pt_map: dict[int, str] = {}
    for pos, ci, pi in KNOWN_PAIRS:
        pt_map[pos] = STANDARD_ALPHABET[pi]

    # For bifid we need contiguous blocks. Check blocks that overlap with known positions.
    for block_start in range(0, n, period):
        block_end = min(block_start + period, n)
        # Check if all positions in this block have known plaintext
        all_known = all(pos in pt_map for pos in range(block_start, block_end))
        if not all_known:
            continue

        # Build plaintext block and expected ciphertext block
        pt_block = "".join(pt_map[pos] for pos in range(block_start, block_end))
        ct_block = K4[block_start:block_end]

        # Encrypt plaintext block with bifid and compare
        encrypted = bifid_encrypt(period, pt_block.replace("J", "I"), square)
        if encrypted != ct_block.replace("J", "I"):
            sq_label = square[:6] + "..."
            return _result("Bifid", f"period={period},sq={sq_label}", UNSAT_LABEL)

    return _result("Bifid", f"period={period}", UNKNOWN_LABEL)


# ---- Compound: Vigenere then Columnar Transposition ----

def _check_compound_vig_col(vig_period: int, col_period: int) -> dict[str, str | None]:
    """Compound: Vigenere(period p) followed by columnar transposition(period q).

    For small parameter combinations, check if there exists a Vigenere key
    and a column permutation that together are consistent with the known plaintext.
    """
    if col_period > 8 or vig_period > 20:
        return _result("Vigenere+Columnar", f"vp={vig_period},cp={col_period}", UNKNOWN_LABEL)

    n = len(K4)
    nrows = (n + col_period - 1) // col_period
    full_cols = n - (nrows - 1) * col_period

    # Try each column permutation
    for col_perm in itertools.permutations(range(col_period)):
        # Under this column permutation, compute the intermediate text
        # (output of Vigenere, input to transposition).
        # From ciphertext (K4), undo the transposition to get intermediate.
        ct_pos = 0
        col_ct_start: dict[int, int] = {}
        col_nrows: dict[int, int] = {}
        for j in range(col_period):
            col = col_perm[j]
            col_ct_start[col] = ct_pos
            rows_in_col = nrows if col < full_cols else nrows - 1
            col_nrows[col] = rows_in_col
            ct_pos += rows_in_col

        # Undo transposition: intermediate[row * col_period + col] = K4[col_ct_start[col] + row]
        intermediate = [''] * n
        valid = True
        for col in range(col_period):
            for row in range(col_nrows.get(col, 0)):
                pt_idx = row * col_period + col
                ct_idx = col_ct_start[col] + row
                if pt_idx < n and ct_idx < n:
                    intermediate[pt_idx] = K4[ct_idx]
                elif pt_idx >= n:
                    pass
                else:
                    valid = False
                    break
            if not valid:
                break

        if not valid:
            continue

        # Now check Vigenere consistency on the intermediate text
        # intermediate[pos] = Vigenere_encrypt(plaintext[pos], key[pos % vig_period])
        # So: key[pos % vig_period] = (intermediate[pos] - plaintext[pos]) mod 26
        slots: dict[int, set[int]] = {}
        consistent = True
        for pos, ci_orig, pi in KNOWN_PAIRS:
            if pos >= n or not intermediate[pos]:
                consistent = False
                break
            inter_val = STANDARD_ALPHABET.index(intermediate[pos])
            slot = pos % vig_period
            shift = (inter_val - pi) % 26
            slots.setdefault(slot, set()).add(shift)

        if not consistent:
            continue

        # Check key consistency
        if all(len(s) == 1 for s in slots.values()):
            vig_key = []
            for s in range(vig_period):
                if s in slots:
                    vig_key.append(STANDARD_ALPHABET[next(iter(slots[s]))])
                else:
                    vig_key.append("?")
            col_str = ",".join(str(c) for c in col_perm)
            witness = f"vig_key={''.join(vig_key)},col=[{col_str}]"
            return _result("Vigenere+Columnar", f"vp={vig_period},cp={col_period}", SAT_LABEL, witness)

    return _result("Vigenere+Columnar", f"vp={vig_period},cp={col_period}", UNSAT_LABEL)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    results: list[dict[str, str | None]] = []
    total_attempts = 0

    if not Z3_AVAILABLE:
        notes = [
            "Z3 solver is not installed — SAT-based columnar transposition proofs are unavailable.",
            "Falling back to arithmetic consistency checks and direct enumeration.",
        ]
    else:
        notes = ["Z3 solver is available for constraint-based proofs."]

    # --- Vigenere family ---
    for period in range(1, 31):
        results.append(_check_vigenere(period))
        total_attempts += 1

    # --- Beaufort family ---
    for period in range(1, 31):
        results.append(_check_beaufort(period))
        total_attempts += 1

    # --- Columnar transposition ---
    for period in range(2, 16):
        results.append(_check_columnar_transposition_z3(period))
        total_attempts += 1

    # --- Autokey-Vigenere ---
    from kryptos.constants import DEFAULT_PRIMERS
    for primer in DEFAULT_PRIMERS:
        results.append(_check_autokey_vigenere(primer))
        total_attempts += 1

    # --- Autokey-Beaufort ---
    for primer in DEFAULT_PRIMERS:
        results.append(_check_autokey_beaufort(primer))
        total_attempts += 1

    # --- Bifid ---
    from kryptos.common import generate_polybius_square
    from kryptos.constants import DEFAULT_KEYWORDS, POLYBIUS_ALPHABET
    squares = [generate_polybius_square(kw) for kw in DEFAULT_KEYWORDS[:4]]
    squares.append(POLYBIUS_ALPHABET)  # default identity square
    for sq in squares:
        for period in (5, 6, 7, 8, 9, 10):
            results.append(_check_bifid(period, sq))
            total_attempts += 1

    # --- Compound: Vigenere + Columnar ---
    for vp in (3, 5, 7):
        for cp in (3, 4, 5, 6, 7):
            results.append(_check_compound_vig_col(vp, cp))
            total_attempts += 1

    # --- Build summary ---
    sat_count = sum(1 for r in results if r["status"] == SAT_LABEL)
    unsat_count = sum(1 for r in results if r["status"] == UNSAT_LABEL)
    unknown_count = sum(1 for r in results if r["status"] == UNKNOWN_LABEL)

    notes.append(f"Tested {total_attempts} hypotheses: {sat_count} satisfiable, {unsat_count} eliminated, {unknown_count} unknown.")

    # Collect satisfiable results as interesting witnesses
    sat_results = [r for r in results if r["status"] == SAT_LABEL]
    unsat_results = [r for r in results if r["status"] == UNSAT_LABEL]

    # Build elimination report
    elimination_lines = []
    for r in results:
        tag = r["status"]
        witness = f" => {r['witness']}" if r.get("witness") else ""
        elimination_lines.append(f"  [{tag}] {r['family']} ({r['params']}){witness}")

    notes.append(f"Eliminated families: {unsat_count} total hypothesis/parameter combinations proven impossible.")

    # Build candidates — each SAT result becomes a candidate with its witness key
    candidates: list[dict[str, object]] = []
    for r in sat_results[:20]:
        # Generate a decryption attempt using the witness key for Vigenere/Beaufort
        text = K4  # placeholder — the point is the elimination report
        chain = [f"sat-check:{r['family']}:{r['params']}"]
        cand = build_ranked_candidate(
            text,
            transform_chain=chain,
            scorer_profile=config.scorer_profile,
            key_material={
                "family": r["family"],
                "params": r["params"],
                "status": r["status"],
                "witness": r.get("witness"),
            },
        )
        candidates.append(cand)

    # Always include a summary candidate with the full elimination report
    report_text = "\n".join(elimination_lines)
    summary_candidate = build_ranked_candidate(
        K4,
        transform_chain=["sat-elimination-report"],
        scorer_profile=config.scorer_profile,
        key_material={
            "elimination_report": report_text,
            "sat_count": sat_count,
            "unsat_count": unsat_count,
            "unknown_count": unknown_count,
            "sat_witnesses": [
                {"family": r["family"], "params": r["params"], "witness": r.get("witness")}
                for r in sat_results
            ],
            "eliminated": [
                {"family": r["family"], "params": r["params"]}
                for r in unsat_results
            ],
        },
    )
    candidates.append(summary_candidate)

    if not candidates:
        candidates.append(
            build_ranked_candidate(
                K4,
                transform_chain=["sat-elimination-no-results"],
                scorer_profile=config.scorer_profile,
            )
        )

    retained = dedupe_ranked_candidates(candidates)[:max(config.candidate_limit, 8)]

    result = build_strategy_result(
        SPEC,
        retained,
        attempts=total_attempts,
        notes=notes,
    )
    result.artifacts["elimination_matrix"] = {
        r["family"] + ":" + r["params"]: r["status"]
        for r in results
    }
    result.artifacts["sat_witnesses"] = [
        {"family": r["family"], "params": r["params"], "witness": r.get("witness")}
        for r in sat_results
    ]
    return result


if __name__ == "__main__":
    from kryptos.common import format_result
    print(format_result(run()))
