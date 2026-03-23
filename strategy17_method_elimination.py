"""Strategy 17 — Known-Plaintext Exhaustive Method Elimination.

Uses pure Python to systematically test cipher families against known
plaintext positions.  For each cipher type and parameter set, the key is
inferred at known positions and checked for internal consistency.
Inconsistencies prove the family+params combination is impossible.

Builds a comprehensive elimination matrix covering:
  - Simple substitution (monoalphabetic)
  - Vigenere (periods 1-50)
  - Beaufort (periods 1-50)
  - Porta cipher (periods 1-50)
  - Autokey-Vigenere (all default primers)
  - Autokey-Beaufort (all default primers)
  - Affine cipher
  - Hill cipher (2x2 and 3x3 matrices)
  - Four-square cipher
  - Two-square cipher
"""

from __future__ import annotations

import math
from typing import Any

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_ranked_candidate,
    build_strategy_result,
    dedupe_ranked_candidates,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    DEFAULT_PRIMERS,
    K4,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig

SPEC = get_strategy_spec("17")

# ---------------------------------------------------------------------------
# Known plaintext pairs  (0-indexed position, cipher_ord 0-25, plain_ord 0-25)
# ---------------------------------------------------------------------------

def _build_known_pairs() -> list[tuple[int, int, int]]:
    """Return sorted list of (0-indexed position, cipher_ord, plain_ord)."""
    pairs: list[tuple[int, int, int]] = []
    for clue, details in ANCHOR_COMPONENT_CLUES.items():
        start = int(details["start_index"]) - 1
        ct = details["ciphertext"]
        for offset, (c_ch, p_ch) in enumerate(zip(ct, clue)):
            ci = STANDARD_ALPHABET.index(c_ch)
            pi = STANDARD_ALPHABET.index(p_ch)
            pairs.append((start + offset, ci, pi))
    pairs.sort()
    return pairs


KNOWN_PAIRS = _build_known_pairs()
ELIMINATED = "ELIMINATED"
CONSISTENT = "CONSISTENT"
UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Porta tableau
# ---------------------------------------------------------------------------

_PORTA_TABLEAU: list[str] = []


def _init_porta() -> list[str]:
    """Build the standard Porta tableau (13 alphabets for pairs of key letters)."""
    if _PORTA_TABLEAU:
        return _PORTA_TABLEAU
    # Porta cipher: 13 substitution alphabets, each a reciprocal substitution
    # on the second half of the alphabet.  Key letter pair (A/B -> row 0,
    # C/D -> row 1, ... Y/Z -> row 12).
    # For each row r, letters A-M map to N+r..Z+r (mod 13, offset by N),
    # and vice versa.
    for r in range(13):
        row = list(STANDARD_ALPHABET)
        for i in range(13):
            j = (i + r) % 13
            row[i] = STANDARD_ALPHABET[13 + j]
            row[13 + j] = STANDARD_ALPHABET[i]
        _PORTA_TABLEAU.append("".join(row))
    return _PORTA_TABLEAU


# ---------------------------------------------------------------------------
# Cipher family testers
# Each returns (status, detail_string)
# ---------------------------------------------------------------------------

def _check_simple_substitution() -> tuple[str, str]:
    """Monoalphabetic substitution: each plaintext letter always maps to the
    same ciphertext letter.  Check that no plaintext letter maps to two
    different ciphertext letters and vice versa."""
    p_to_c: dict[int, int] = {}
    c_to_p: dict[int, int] = {}
    for pos, ci, pi in KNOWN_PAIRS:
        if pi in p_to_c:
            if p_to_c[pi] != ci:
                return (ELIMINATED, f"P={STANDARD_ALPHABET[pi]} maps to both "
                        f"{STANDARD_ALPHABET[p_to_c[pi]]} and {STANDARD_ALPHABET[ci]}")
        else:
            p_to_c[pi] = ci

        if ci in c_to_p:
            if c_to_p[ci] != pi:
                return (ELIMINATED, f"C={STANDARD_ALPHABET[ci]} maps from both "
                        f"{STANDARD_ALPHABET[c_to_p[ci]]} and {STANDARD_ALPHABET[pi]}")
        else:
            c_to_p[ci] = pi

    partial_key = {STANDARD_ALPHABET[pi]: STANDARD_ALPHABET[ci] for pi, ci in p_to_c.items()}
    return (CONSISTENT, f"partial_mapping={partial_key}")


def _check_vigenere(period: int) -> tuple[str, str]:
    """Vigenere with repeating key of given period."""
    slots: dict[int, set[int]] = {}
    for pos, ci, pi in KNOWN_PAIRS:
        slot = pos % period
        shift = (ci - pi) % 26
        slots.setdefault(slot, set()).add(shift)

    for slot, shifts in slots.items():
        if len(shifts) > 1:
            letters = [STANDARD_ALPHABET[s] for s in sorted(shifts)]
            return (ELIMINATED, f"slot {slot} requires shifts {letters}")

    key = []
    for s in range(period):
        if s in slots:
            key.append(STANDARD_ALPHABET[next(iter(slots[s]))])
        else:
            key.append("?")
    return (CONSISTENT, f"key={''.join(key)}")


def _check_beaufort(period: int) -> tuple[str, str]:
    """Beaufort with repeating key of given period."""
    slots: dict[int, set[int]] = {}
    for pos, ci, pi in KNOWN_PAIRS:
        slot = pos % period
        shift = (pi - ci) % 26
        slots.setdefault(slot, set()).add(shift)

    for slot, shifts in slots.items():
        if len(shifts) > 1:
            letters = [STANDARD_ALPHABET[s] for s in sorted(shifts)]
            return (ELIMINATED, f"slot {slot} requires shifts {letters}")

    key = []
    for s in range(period):
        if s in slots:
            key.append(STANDARD_ALPHABET[next(iter(slots[s]))])
        else:
            key.append("?")
    return (CONSISTENT, f"key={''.join(key)}")


def _check_porta(period: int) -> tuple[str, str]:
    """Porta cipher with repeating key of given period.

    Porta: key letter determines which of 13 reciprocal alphabets to use.
    Key letters are grouped in pairs: A/B -> tableau row 0, C/D -> row 1, etc.
    So the effective key slot has 13 possible values (not 26).
    """
    tableau = _init_porta()
    slots: dict[int, set[int]] = {}

    for pos, ci, pi in KNOWN_PAIRS:
        slot = pos % period
        # Find which tableau rows map plaintext letter pi to ciphertext letter ci
        possible_rows: set[int] = set()
        for r in range(13):
            # Porta is reciprocal: tableau[r][pi] gives the encrypted ordinal
            row_str = tableau[r]
            if STANDARD_ALPHABET.index(row_str[pi]) == ci:
                possible_rows.add(r)
        slots.setdefault(slot, []).append(possible_rows)  # type: ignore[arg-type]

    # For each slot, intersect possible row sets
    for slot, row_sets in slots.items():  # type: ignore[assignment]
        intersection = row_sets[0]
        for rs in row_sets[1:]:
            intersection = intersection & rs
        if not intersection:
            return (ELIMINATED, f"slot {slot} has no valid Porta key row")

    return (CONSISTENT, f"period={period}")


def _check_autokey_vigenere(primer: str) -> tuple[str, str]:
    """Autokey-Vigenere with given primer.  Key stream = primer + plaintext."""
    plen = len(primer)
    inferred_plain: dict[int, int] = {}

    for pos, ci, pi in KNOWN_PAIRS:
        inferred_plain[pos] = pi

    for pos, ci, pi in KNOWN_PAIRS:
        key_val = (ci - pi) % 26
        if pos < plen:
            expected = STANDARD_ALPHABET.index(primer[pos])
            if key_val != expected:
                return (ELIMINATED, f"pos {pos}: key must be {STANDARD_ALPHABET[key_val]} "
                        f"but primer has {primer[pos]}")
        else:
            source_pos = pos - plen
            if source_pos in inferred_plain:
                if key_val != inferred_plain[source_pos]:
                    return (ELIMINATED, f"pos {pos}: key requires P[{source_pos}]="
                            f"{STANDARD_ALPHABET[key_val]} but known P[{source_pos}]="
                            f"{STANDARD_ALPHABET[inferred_plain[source_pos]]}")
            else:
                inferred_plain[source_pos] = key_val

    return (CONSISTENT, f"primer={primer}")


def _check_autokey_beaufort(primer: str) -> tuple[str, str]:
    """Autokey-Beaufort with given primer.  C = (key - P) mod 26."""
    plen = len(primer)
    inferred_plain: dict[int, int] = {}

    for pos, ci, pi in KNOWN_PAIRS:
        inferred_plain[pos] = pi

    for pos, ci, pi in KNOWN_PAIRS:
        key_val = (ci + pi) % 26
        if pos < plen:
            expected = STANDARD_ALPHABET.index(primer[pos])
            if key_val != expected:
                return (ELIMINATED, f"pos {pos}: key must be {STANDARD_ALPHABET[key_val]} "
                        f"but primer has {primer[pos]}")
        else:
            source_pos = pos - plen
            if source_pos in inferred_plain:
                if key_val != inferred_plain[source_pos]:
                    return (ELIMINATED, f"pos {pos}: key requires P[{source_pos}]="
                            f"{STANDARD_ALPHABET[key_val]} but known P[{source_pos}]="
                            f"{STANDARD_ALPHABET[inferred_plain[source_pos]]}")
            else:
                inferred_plain[source_pos] = key_val

    return (CONSISTENT, f"primer={primer}")


def _check_affine() -> tuple[str, str]:
    """Affine cipher: C = (a*P + b) mod 26.  a must be coprime with 26.

    From two known pairs we can solve for a and b. If any third pair
    contradicts, the cipher is eliminated.
    """
    valid_a = [a for a in range(26) if math.gcd(a, 26) == 1]

    # Try all valid (a, b) and check consistency
    consistent_params: list[tuple[int, int]] = []
    for a in valid_a:
        for b in range(26):
            ok = True
            for pos, ci, pi in KNOWN_PAIRS:
                if (a * pi + b) % 26 != ci:
                    ok = False
                    break
            if ok:
                consistent_params.append((a, b))

    if not consistent_params:
        return (ELIMINATED, "no (a,b) pair satisfies all known positions")

    params_str = ", ".join(f"a={a},b={b}" for a, b in consistent_params[:5])
    return (CONSISTENT, f"valid params: {params_str}")


def _mod_inverse(a: int, m: int) -> int | None:
    """Extended Euclidean to find modular inverse of a mod m."""
    if math.gcd(a, m) != 1:
        return None
    g, x, _ = _extended_gcd(a, m)
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _check_hill_2x2() -> tuple[str, str]:
    """Hill cipher with 2x2 key matrix.

    Encryption: [C1, C2] = K * [P1, P2] mod 26 (column vectors).
    From known pairs at consecutive even positions, we can derive
    constraints on the key matrix.
    """
    # Group known pairs into consecutive pairs (positions i, i+1)
    pos_map = {pos: (ci, pi) for pos, ci, pi in KNOWN_PAIRS}
    pair_blocks: list[tuple[int, int, int, int, int, int]] = []

    sorted_positions = sorted(pos_map.keys())
    for i in range(len(sorted_positions) - 1):
        p1 = sorted_positions[i]
        p2 = sorted_positions[i + 1]
        if p2 == p1 + 1 and p1 % 2 == 0:
            c1, pl1 = pos_map[p1]
            c2, pl2 = pos_map[p2]
            pair_blocks.append((p1, pl1, pl2, c1, c2, p2))

    if len(pair_blocks) < 2:
        return (UNKNOWN, "insufficient consecutive pairs for 2x2 Hill")

    # For each pair of blocks, try to solve for the key matrix
    # K * [P1 P3; P2 P4] = [C1 C3; C2 C4] mod 26
    # K = [C1 C3; C2 C4] * [P1 P3; P2 P4]^-1 mod 26
    eliminated = True
    for i in range(len(pair_blocks)):
        for j in range(i + 1, len(pair_blocks)):
            _, p1, p2, c1, c2, _ = pair_blocks[i]
            _, p3, p4, c3, c4, _ = pair_blocks[j]

            # Plaintext matrix P = [[p1, p3], [p2, p4]]
            det_p = (p1 * p4 - p2 * p3) % 26
            det_inv = _mod_inverse(det_p, 26)
            if det_inv is None:
                continue

            # P^-1 = det_inv * [[p4, -p3], [-p2, p1]] mod 26
            p_inv = [
                [(det_inv * p4) % 26, (det_inv * (-p3)) % 26],
                [(det_inv * (-p2)) % 26, (det_inv * p1) % 26],
            ]

            # K = C * P^-1
            c_mat = [[c1, c3], [c2, c4]]
            k_mat = [
                [(c_mat[0][0] * p_inv[0][0] + c_mat[0][1] * p_inv[1][0]) % 26,
                 (c_mat[0][0] * p_inv[0][1] + c_mat[0][1] * p_inv[1][1]) % 26],
                [(c_mat[1][0] * p_inv[0][0] + c_mat[1][1] * p_inv[1][0]) % 26,
                 (c_mat[1][0] * p_inv[0][1] + c_mat[1][1] * p_inv[1][1]) % 26],
            ]

            # Verify K against all other pair blocks
            valid = True
            for k in range(len(pair_blocks)):
                if k == i or k == j:
                    continue
                _, pp1, pp2, cc1, cc2, _ = pair_blocks[k]
                ec1 = (k_mat[0][0] * pp1 + k_mat[0][1] * pp2) % 26
                ec2 = (k_mat[1][0] * pp1 + k_mat[1][1] * pp2) % 26
                if ec1 != cc1 or ec2 != cc2:
                    valid = False
                    break

            if valid:
                return (CONSISTENT, f"key_matrix={k_mat}")

    if eliminated:
        return (ELIMINATED, "no consistent 2x2 key matrix found")

    return (UNKNOWN, "could not determine")


def _check_hill_3x3() -> tuple[str, str]:
    """Hill cipher with 3x3 key matrix.

    Need groups of 3 consecutive known positions aligned on block boundaries.
    """
    pos_map = {pos: (ci, pi) for pos, ci, pi in KNOWN_PAIRS}
    sorted_positions = sorted(pos_map.keys())

    # Find triplets at positions (3k, 3k+1, 3k+2)
    triplets: list[tuple[int, int, int, int, int, int, int]] = []
    for i in range(len(sorted_positions) - 2):
        p1 = sorted_positions[i]
        p2 = sorted_positions[i + 1]
        p3 = sorted_positions[i + 2]
        if p2 == p1 + 1 and p3 == p1 + 2 and p1 % 3 == 0:
            c1, pl1 = pos_map[p1]
            c2, pl2 = pos_map[p2]
            c3, pl3 = pos_map[p3]
            triplets.append((p1, pl1, pl2, pl3, c1, c2, c3))

    if len(triplets) < 3:
        return (UNKNOWN, "insufficient aligned triplets for 3x3 Hill")

    # Try solving K from first 3 triplets, verify against rest
    for i in range(len(triplets)):
        for j in range(i + 1, len(triplets)):
            for k_idx in range(j + 1, len(triplets)):
                _, p11, p12, p13, c11, c12, c13 = triplets[i]
                _, p21, p22, p23, c21, c22, c23 = triplets[j]
                _, p31, p32, p33, c31, c32, c33 = triplets[k_idx]

                # Build plaintext matrix (3x3)
                P = [[p11, p21, p31],
                     [p12, p22, p32],
                     [p13, p23, p33]]

                det = _det3(P)
                det_inv = _mod_inverse(det % 26, 26)
                if det_inv is None:
                    continue

                # Compute adjugate matrix
                adj = _adjugate3(P)
                P_inv = [[(det_inv * adj[r][c]) % 26 for c in range(3)] for r in range(3)]

                C = [[c11, c21, c31],
                     [c12, c22, c32],
                     [c13, c23, c33]]

                # K = C * P_inv mod 26
                K_mat = [[sum(C[r][m] * P_inv[m][c] for m in range(3)) % 26
                          for c in range(3)] for r in range(3)]

                # Verify against remaining triplets
                valid = True
                for t_idx in range(len(triplets)):
                    if t_idx in (i, j, k_idx):
                        continue
                    _, tp1, tp2, tp3, tc1, tc2, tc3 = triplets[t_idx]
                    pv = [tp1, tp2, tp3]
                    cv = [tc1, tc2, tc3]
                    for row in range(3):
                        expected = sum(K_mat[row][m] * pv[m] for m in range(3)) % 26
                        if expected != cv[row]:
                            valid = False
                            break
                    if not valid:
                        break

                if valid:
                    return (CONSISTENT, f"key_matrix_3x3={K_mat}")

    return (ELIMINATED, "no consistent 3x3 key matrix found")


def _det3(m: list[list[int]]) -> int:
    return (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))


def _adjugate3(m: list[list[int]]) -> list[list[int]]:
    """Compute the adjugate (transpose of cofactor matrix) for a 3x3 matrix."""
    cofactors = [[0] * 3 for _ in range(3)]
    for r in range(3):
        for c in range(3):
            minor = []
            for rr in range(3):
                if rr == r:
                    continue
                row = []
                for cc in range(3):
                    if cc == c:
                        continue
                    row.append(m[rr][cc])
                minor.append(row)
            cof = minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0]
            cofactors[r][c] = ((-1) ** (r + c)) * cof
    # Transpose
    return [[cofactors[c][r] for c in range(3)] for r in range(3)]


def _check_four_square() -> tuple[str, str]:
    """Four-square cipher: digraph substitution using two keyed alphabets.

    In four-square, plaintext is split into digraphs. Each digraph (a,b)
    is encrypted using two 5x5 Polybius squares Q1, Q2:
      - Find a in standard square (row r1, col c1)
      - Find b in standard square (row r2, col c2)
      - Ciphertext first letter = Q1[r1][c2]
      - Ciphertext second letter = Q2[r2][c1]

    We check if the known plaintext digraphs at even-aligned positions
    yield a consistent pair of keyed squares.
    """
    pos_map = {pos: (ci, pi) for pos, ci, pi in KNOWN_PAIRS}
    sorted_positions = sorted(pos_map.keys())

    # Find digraph pairs at even positions
    digraphs: list[tuple[int, int, int, int]] = []
    for i in range(len(sorted_positions) - 1):
        p1 = sorted_positions[i]
        p2 = sorted_positions[i + 1]
        if p2 == p1 + 1 and p1 % 2 == 0:
            c1, pl1 = pos_map[p1]
            c2, pl2 = pos_map[p2]
            digraphs.append((pl1, pl2, c1, c2))

    if len(digraphs) < 2:
        return (UNKNOWN, "insufficient digraph pairs for four-square analysis")

    # In four-square with standard plain squares:
    # p1 -> (r1, c1) in standard, p2 -> (r2, c2) in standard
    # C1 = Q1[r1, c2], C2 = Q2[r2, c1]
    # This means Q1[r1, c2] is constrained and Q2[r2, c1] is constrained.
    # Check for contradictions: if two digraphs need Q1[r, c] to be different letters.

    # Use 5x5 grids (J=I mapping)
    POLY = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def to_poly(ch_idx: int) -> int:
        ch = STANDARD_ALPHABET[ch_idx]
        if ch == 'J':
            ch = 'I'
        return POLY.index(ch)

    q1_constraints: dict[tuple[int, int], set[int]] = {}
    q2_constraints: dict[tuple[int, int], set[int]] = {}

    for pl1, pl2, c1, c2 in digraphs:
        pp1 = to_poly(pl1)
        pp2 = to_poly(pl2)
        cc1 = to_poly(c1)
        cc2 = to_poly(c2)

        r1, col1 = pp1 // 5, pp1 % 5
        r2, col2 = pp2 // 5, pp2 % 5

        key1 = (r1, col2)
        key2 = (r2, col1)

        q1_constraints.setdefault(key1, set()).add(cc1)
        q2_constraints.setdefault(key2, set()).add(cc2)

    # Check for contradictions
    for key, vals in q1_constraints.items():
        if len(vals) > 1:
            return (ELIMINATED, f"Q1[{key}] must be multiple letters: {vals}")
    for key, vals in q2_constraints.items():
        if len(vals) > 1:
            return (ELIMINATED, f"Q2[{key}] must be multiple letters: {vals}")

    return (CONSISTENT, f"four-square: {len(q1_constraints)} Q1 + {len(q2_constraints)} Q2 constraints, no contradictions")


def _check_two_square() -> tuple[str, str]:
    """Two-square (double Playfair) cipher.

    Horizontal two-square: digraph (a,b) encrypted by finding a in Q1
    and b in Q2, then taking letters from the rectangle corners.
    """
    pos_map = {pos: (ci, pi) for pos, ci, pi in KNOWN_PAIRS}
    sorted_positions = sorted(pos_map.keys())

    digraphs: list[tuple[int, int, int, int]] = []
    for i in range(len(sorted_positions) - 1):
        p1 = sorted_positions[i]
        p2 = sorted_positions[i + 1]
        if p2 == p1 + 1 and p1 % 2 == 0:
            c1, pl1 = pos_map[p1]
            c2, pl2 = pos_map[p2]
            digraphs.append((pl1, pl2, c1, c2))

    if len(digraphs) < 2:
        return (UNKNOWN, "insufficient digraph pairs for two-square analysis")

    # Horizontal two-square:
    # a in Q1 at (r1, c1), b in Q2 at (r2, c2)
    # If r1 == r2: C1 = Q1[r1, c2], C2 = Q2[r2, c1] (same row -> swap columns)
    # If r1 != r2: C1 = Q1[r1, c2], C2 = Q2[r2, c1] (rectangle)
    # Same constraint structure as four-square for general analysis.

    POLY = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def to_poly(ch_idx: int) -> int:
        ch = STANDARD_ALPHABET[ch_idx]
        if ch == 'J':
            ch = 'I'
        return POLY.index(ch)

    # Without knowing Q1 and Q2, we check if consistent assignment exists
    # For two-square, the constraint is:
    # Q1[r_a, c_b_in_Q2] = C1 and Q2[r_b, c_a_in_Q1] = C2
    # where positions depend on the unknown squares.
    # This is underconstrained without more info, so report CONSISTENT/UNKNOWN.
    return (UNKNOWN, f"two-square: {len(digraphs)} digraphs available, "
            "underconstrained without known square structure")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    elimination: dict[str, tuple[str, str]] = {}
    total_attempts = 0

    # --- Simple substitution ---
    elimination["SimpleSubstitution"] = _check_simple_substitution()
    total_attempts += 1

    # --- Vigenere (periods 1-50) ---
    for period in range(1, 51):
        elimination[f"Vigenere:period={period}"] = _check_vigenere(period)
        total_attempts += 1

    # --- Beaufort (periods 1-50) ---
    for period in range(1, 51):
        elimination[f"Beaufort:period={period}"] = _check_beaufort(period)
        total_attempts += 1

    # --- Porta (periods 1-50) ---
    for period in range(1, 51):
        elimination[f"Porta:period={period}"] = _check_porta(period)
        total_attempts += 1

    # --- Autokey-Vigenere ---
    for primer in DEFAULT_PRIMERS:
        elimination[f"AutokeyVigenere:primer={primer}"] = _check_autokey_vigenere(primer)
        total_attempts += 1

    # --- Autokey-Beaufort ---
    for primer in DEFAULT_PRIMERS:
        elimination[f"AutokeyBeaufort:primer={primer}"] = _check_autokey_beaufort(primer)
        total_attempts += 1

    # --- Affine ---
    elimination["Affine"] = _check_affine()
    total_attempts += 1

    # --- Hill 2x2 ---
    elimination["Hill:2x2"] = _check_hill_2x2()
    total_attempts += 1

    # --- Hill 3x3 ---
    elimination["Hill:3x3"] = _check_hill_3x3()
    total_attempts += 1

    # --- Four-square ---
    elimination["FourSquare"] = _check_four_square()
    total_attempts += 1

    # --- Two-square ---
    elimination["TwoSquare"] = _check_two_square()
    total_attempts += 1

    # --- Build summary ---
    eliminated_count = sum(1 for s, _ in elimination.values() if s == ELIMINATED)
    consistent_count = sum(1 for s, _ in elimination.values() if s == CONSISTENT)
    unknown_count = sum(1 for s, _ in elimination.values() if s == UNKNOWN)

    # Build per-family summaries
    families: dict[str, dict[str, int]] = {}
    for key, (status, _) in elimination.items():
        family = key.split(":")[0]
        families.setdefault(family, {"eliminated": 0, "consistent": 0, "unknown": 0})
        if status == ELIMINATED:
            families[family]["eliminated"] += 1
        elif status == CONSISTENT:
            families[family]["consistent"] += 1
        else:
            families[family]["unknown"] += 1

    family_summary_lines = []
    for fam, counts in sorted(families.items()):
        total = counts["eliminated"] + counts["consistent"] + counts["unknown"]
        family_summary_lines.append(
            f"  {fam}: {counts['eliminated']}/{total} eliminated, "
            f"{counts['consistent']} consistent, {counts['unknown']} unknown"
        )

    # Collect consistent Vigenere keys for reporting
    consistent_vig_keys: list[str] = []
    for period in range(1, 51):
        key = f"Vigenere:period={period}"
        if key in elimination and elimination[key][0] == CONSISTENT:
            consistent_vig_keys.append(f"p={period}: {elimination[key][1]}")

    notes = [
        f"Tested {total_attempts} cipher family+parameter combinations.",
        f"Results: {eliminated_count} eliminated, {consistent_count} consistent, {unknown_count} unknown.",
        "Family breakdown:",
        *family_summary_lines,
    ]

    if consistent_vig_keys:
        notes.append(f"Consistent Vigenere periods: {len(consistent_vig_keys)} out of 50")

    # Build elimination report for key_material
    report_lines = []
    for key, (status, detail) in sorted(elimination.items()):
        report_lines.append(f"  [{status}] {key}: {detail}")

    # Build candidates
    candidates: list[dict[str, object]] = []

    # Primary candidate: elimination report summary
    summary_candidate = build_ranked_candidate(
        K4,
        transform_chain=["method-elimination-report"],
        scorer_profile=config.scorer_profile,
        key_material={
            "elimination_matrix": {k: {"status": s, "detail": d} for k, (s, d) in elimination.items()},
            "family_summary": families,
            "eliminated_count": eliminated_count,
            "consistent_count": consistent_count,
            "unknown_count": unknown_count,
            "consistent_vigenere_keys": consistent_vig_keys,
            "report": "\n".join(report_lines),
        },
    )
    candidates.append(summary_candidate)

    # Add candidates for each consistent Vigenere key (try actual decryption)
    from kryptos.common import decrypt_vigenere_standard
    for period in range(1, 51):
        key_label = f"Vigenere:period={period}"
        if key_label in elimination and elimination[key_label][0] == CONSISTENT:
            detail = elimination[key_label][1]
            # Extract key from detail string "key=XXXX"
            if "key=" in detail:
                vig_key = detail.split("key=")[1]
                if "?" not in vig_key:
                    pt = decrypt_vigenere_standard(K4, vig_key)
                    cand = build_ranked_candidate(
                        pt,
                        transform_chain=[f"vigenere:period={period}:key={vig_key}"],
                        scorer_profile=config.scorer_profile,
                        key_material={
                            "cipher": "Vigenere",
                            "period": period,
                            "key": vig_key,
                            "status": CONSISTENT,
                        },
                    )
                    candidates.append(cand)

    # Add candidates for each consistent Beaufort key
    for period in range(1, 51):
        key_label = f"Beaufort:period={period}"
        if key_label in elimination and elimination[key_label][0] == CONSISTENT:
            detail = elimination[key_label][1]
            if "key=" in detail:
                beau_key = detail.split("key=")[1]
                if "?" not in beau_key:
                    # Beaufort decryption: P = (key - C) mod 26
                    pt_chars = []
                    for idx, ch in enumerate(K4):
                        k_ch = beau_key[idx % len(beau_key)]
                        pt_chars.append(STANDARD_ALPHABET[
                            (STANDARD_ALPHABET.index(k_ch) - STANDARD_ALPHABET.index(ch)) % 26
                        ])
                    pt = "".join(pt_chars)
                    cand = build_ranked_candidate(
                        pt,
                        transform_chain=[f"beaufort:period={period}:key={beau_key}"],
                        scorer_profile=config.scorer_profile,
                        key_material={
                            "cipher": "Beaufort",
                            "period": period,
                            "key": beau_key,
                            "status": CONSISTENT,
                        },
                    )
                    candidates.append(cand)

    if not candidates:
        candidates.append(
            build_ranked_candidate(
                K4,
                transform_chain=["method-elimination-no-results"],
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
        k: {"status": s, "detail": d} for k, (s, d) in elimination.items()
    }
    result.artifacts["family_summary"] = families
    return result


if __name__ == "__main__":
    from kryptos.common import format_result
    print(format_result(run()))
