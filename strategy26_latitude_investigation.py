"""Strategy 26: LATITUDE Deep Investigation.

The previous session discovered that the transposition keyword LATITUDE
(permutation [1,5,3,0,2,4], width 6) produced the highest-scoring K4
candidate at 772/1000 with all four anchors matching. However, the
non-anchor plaintext is gibberish, suggesting the substitution model
(standard Vigenere p=28) is wrong or there's an additional layer.

This script deeply investigates the LATITUDE finding:
1. LATITUDE transposition + ALL Vigenere periods (2-97)
2. LATITUDE transposition + Beaufort cipher
3. LATITUDE transposition + Quagmire III (KRYPTOS alphabet)
4. LATITUDE + LONGITUDE: LONGITUDE as Vigenere key, LATITUDE as transposition
5. Geographic keyword transpositions with all substitution models
6. REVERSE cipher order: Vigenere FIRST, THEN transposition
7. Double transposition: LATITUDE + second keyword
"""
from __future__ import annotations

import sys
import time
import random
import math
import json
from itertools import permutations as iter_perms

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, ANCHOR_COMPONENT_CLUES, KNOWN_PLAINTEXT_CLUES,
    STANDARD_ALPHABET, KRYPTOS_ALPHABET,
)
from kryptos.common import (
    anchor_alignment_score, language_shape_score, build_score_breakdown,
    decrypt_vigenere_standard, normalize_letters,
)
from kryptos.transposition import (
    periodic_transposition_decrypt, periodic_transposition_encrypt,
    keyword_permutation, identity_permutation,
)

# ---------------------------------------------------------------------------
# Known plaintext (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _c, _d in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_c, int(_d["start_index"]) - 1))

KNOWN_PT: dict[int, str] = {}
for clue, start in ANCHORS:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

N = len(K4)

# ---------------------------------------------------------------------------
# Geographic keywords to test as transposition keys
# ---------------------------------------------------------------------------
GEO_KEYWORDS = [
    "LATITUDE", "LONGITUDE", "COORDINATES", "DEGREES", "MINUTES",
    "SECONDS", "POSITION", "BEARING", "HEADING", "MERIDIAN",
    "EQUATOR", "COMPASS", "NAVIGATE", "THIRTYEIGHT", "SEVENTYSEVEN",
    "NORTH", "WEST", "PALIMPSEST", "ABSCISSA",
]

# ---------------------------------------------------------------------------
# N-gram scorer
# ---------------------------------------------------------------------------
BIGRAM_LOG: dict[str, float] = {
    "TH": -1.22, "HE": -1.28, "IN": -1.44, "ER": -1.48, "AN": -1.52,
    "RE": -1.58, "ON": -1.65, "AT": -1.70, "EN": -1.72, "ND": -1.74,
    "TI": -1.76, "ES": -1.78, "OR": -1.80, "TE": -1.82, "OF": -1.84,
    "ED": -1.86, "IS": -1.88, "IT": -1.90, "AL": -1.92, "AR": -1.94,
    "ST": -1.96, "TO": -1.98, "NT": -2.00, "NG": -2.02, "SE": -2.04,
    "HA": -2.06, "AS": -2.08, "OU": -2.10, "IO": -2.12, "LE": -2.14,
    "VE": -2.16, "CO": -2.18, "ME": -2.20, "DE": -2.22, "HI": -2.24,
    "RI": -2.26, "RO": -2.28, "IC": -2.30, "NE": -2.32, "EA": -2.34,
    "RA": -2.36, "CE": -2.38, "LI": -2.40, "CH": -2.42, "LL": -2.44,
    "BE": -2.46, "MA": -2.48, "SI": -2.50, "OM": -2.52, "UR": -2.54,
    "CA": -2.56, "EL": -2.58, "TA": -2.60, "LA": -2.62, "NS": -2.64,
    "GE": -2.66, "LO": -2.68, "US": -2.70, "PE": -2.72, "EC": -2.74,
    "WA": -2.76, "WH": -2.78, "EE": -2.80, "NO": -2.82, "DO": -2.84,
    "TR": -2.86, "DI": -2.88, "WI": -2.90, "SO": -2.92, "IF": -2.94,
    "TT": -2.96, "LY": -2.98, "SS": -3.00, "FO": -3.02, "UL": -3.04,
    "CT": -3.06, "HO": -3.08, "OT": -3.10, "PR": -3.12, "SH": -3.14,
}
TRIGRAM_LOG: dict[str, float] = {
    "THE": -1.78, "AND": -2.15, "ING": -2.28, "ION": -2.52, "TIO": -2.56,
    "ENT": -2.60, "ERE": -2.68, "HER": -2.72, "ATE": -2.75, "VER": -2.78,
    "TER": -2.80, "THA": -2.82, "ATI": -2.84, "HAT": -2.86, "ALL": -2.88,
    "ETH": -2.90, "FOR": -2.92, "HIS": -2.94, "NOT": -2.96, "TED": -2.98,
    "EST": -3.00, "ERS": -3.02, "ITH": -3.04, "NTH": -3.06, "INT": -3.08,
    "ANT": -3.10, "ONE": -3.12, "OFT": -3.14, "STH": -3.16, "MEN": -3.18,
    "OUR": -3.20, "RED": -3.22, "IVE": -3.24, "NDE": -3.26, "OUN": -3.28,
    "IST": -3.30, "AIN": -3.32, "ORT": -3.34, "URE": -3.36, "STR": -3.38,
    "NES": -3.40, "AVE": -3.42, "ECT": -3.44, "RES": -3.46, "COM": -3.48,
    "PRO": -3.50, "ARE": -3.52, "OUT": -3.54, "WIT": -3.56, "EAR": -3.58,
}
OTHER_BG = -4.5
OTHER_TG = -5.5


def ngram_score(text: str) -> float:
    s = 0.0
    for i in range(len(text) - 1):
        s += BIGRAM_LOG.get(text[i:i+2], OTHER_BG)
    for i in range(len(text) - 2):
        s += TRIGRAM_LOG.get(text[i:i+3], OTHER_TG) * 1.5
    return s


def anchor_hits(text: str) -> int:
    hits = 0
    for clue, start in ANCHORS:
        end = start + len(clue)
        if end <= len(text):
            hits += sum(1 for a, b in zip(text[start:end], clue) if a == b)
    return hits


# ---------------------------------------------------------------------------
# Substitution cipher models
# ---------------------------------------------------------------------------
def check_vigenere_consistency(inter: str, period: int) -> dict | None:
    """Check if standard Vigenere with given period satisfies all anchors."""
    slot_reqs: dict[int, set[int]] = {}
    for pos, pch in KNOWN_PT.items():
        if pos >= len(inter):
            return None
        shift = (ord(inter[pos]) - ord(pch)) % 26
        slot = pos % period
        if slot not in slot_reqs:
            slot_reqs[slot] = set()
        slot_reqs[slot].add(shift)

    key_shifts = [-1] * period
    for slot, shifts in slot_reqs.items():
        if len(shifts) != 1:
            return None
        key_shifts[slot] = shifts.pop()

    return {"key_shifts": key_shifts, "constrained": sum(1 for s in key_shifts if s >= 0)}


def check_beaufort_consistency(inter: str, period: int) -> dict | None:
    """Beaufort: C = (K - P) mod 26, so K = (C + P) mod 26."""
    slot_reqs: dict[int, set[int]] = {}
    for pos, pch in KNOWN_PT.items():
        if pos >= len(inter):
            return None
        shift = (ord(inter[pos]) - 65 + ord(pch) - 65) % 26
        slot = pos % period
        if slot not in slot_reqs:
            slot_reqs[slot] = set()
        slot_reqs[slot].add(shift)

    key_shifts = [-1] * period
    for slot, shifts in slot_reqs.items():
        if len(shifts) != 1:
            return None
        key_shifts[slot] = shifts.pop()

    return {"key_shifts": key_shifts, "constrained": sum(1 for s in key_shifts if s >= 0)}


# Build Quagmire III lookup tables
_KRYP_TO_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}

def check_quagmire_consistency(inter: str, period: int) -> dict | None:
    """Quagmire III: tableau row = KRYPTOS_ALPHABET shifted by key index.
    For cipher char C at position with key shift k:
      shifted_row = KRYPTOS_ALPHABET[k:] + KRYPTOS_ALPHABET[:k]
      C is at position p in shifted_row -> plain = KRYPTOS_ALPHABET[p]
    So: k = (KRYP_IDX[C] - KRYP_IDX[P]) mod 26
    """
    slot_reqs: dict[int, set[int]] = {}
    for pos, pch in KNOWN_PT.items():
        if pos >= len(inter):
            return None
        cch = inter[pos]
        if cch not in _KRYP_TO_IDX or pch not in _KRYP_TO_IDX:
            return None
        shift = (_KRYP_TO_IDX[cch] - _KRYP_TO_IDX[pch]) % 26
        slot = pos % period
        if slot not in slot_reqs:
            slot_reqs[slot] = set()
        slot_reqs[slot].add(shift)

    key_shifts = [-1] * period
    for slot, shifts in slot_reqs.items():
        if len(shifts) != 1:
            return None
        key_shifts[slot] = shifts.pop()

    return {"key_shifts": key_shifts, "constrained": sum(1 for s in key_shifts if s >= 0)}


# ---------------------------------------------------------------------------
# Decryption functions for each model
# ---------------------------------------------------------------------------
def decrypt_vigenere_shifts(inter: str, shifts: list[int], period: int) -> str:
    result = []
    for i, c in enumerate(inter):
        s = shifts[i % period]
        if s < 0:
            s = 0
        result.append(STANDARD_ALPHABET[(ord(c) - 65 - s) % 26])
    return "".join(result)


def decrypt_beaufort_shifts(inter: str, shifts: list[int], period: int) -> str:
    """Beaufort decryption: P = (K - C) mod 26."""
    result = []
    for i, c in enumerate(inter):
        k = shifts[i % period]
        if k < 0:
            k = 0
        result.append(STANDARD_ALPHABET[(k - (ord(c) - 65)) % 26])
    return "".join(result)


def decrypt_quagmire_shifts(inter: str, shifts: list[int], period: int) -> str:
    """Quagmire III decryption with shift-based key."""
    result = []
    for i, c in enumerate(inter):
        k = shifts[i % period]
        if k < 0:
            k = 0
        if c not in _KRYP_TO_IDX:
            result.append(c)
            continue
        ci = _KRYP_TO_IDX[c]
        pi = (ci - k) % 26
        result.append(KRYPTOS_ALPHABET[pi])
    return "".join(result)


# ---------------------------------------------------------------------------
# MCMC optimizer
# ---------------------------------------------------------------------------
def optimize_unconstrained(inter: str, key_shifts: list[int], period: int,
                            decrypt_fn, rng: random.Random,
                            num_steps: int = 5000) -> tuple[list[int], str, float]:
    shifts = list(key_shifts)
    unconstrained = [i for i in range(period) if shifts[i] < 0]
    for slot in unconstrained:
        shifts[slot] = rng.randrange(26)

    text = decrypt_fn(inter, shifts, period)
    score = ngram_score(text)
    best_shifts = list(shifts)
    best_text = text
    best_score = score

    if not unconstrained:
        return best_shifts, best_text, best_score

    for step in range(num_steps):
        temp = 3.0 - 2.9 * step / num_steps
        slot = unconstrained[rng.randrange(len(unconstrained))]
        old = shifts[slot]
        shifts[slot] = rng.randrange(26)
        new_text = decrypt_fn(inter, shifts, period)
        new_score = ngram_score(new_text)
        delta = (new_score - score) / max(temp, 0.01)
        if delta > 0 or rng.random() < math.exp(min(delta, 50)):
            score = new_score
            text = new_text
            if score > best_score:
                best_score = score
                best_shifts = list(shifts)
                best_text = text
        else:
            shifts[slot] = old

    return best_shifts, best_text, best_score


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    rng = random.Random(2026_03_21_26)
    t0 = time.perf_counter()
    all_candidates: list[dict] = []

    cipher_models = [
        ("vigenere", check_vigenere_consistency, decrypt_vigenere_shifts),
        ("beaufort", check_beaufort_consistency, decrypt_beaufort_shifts),
        ("quagmire3", check_quagmire_consistency, decrypt_quagmire_shifts),
    ]

    # ===================================================================
    # PHASE 1: LATITUDE transposition + ALL cipher models + ALL periods
    # ===================================================================
    print("=" * 72)
    print("PHASE 1: LATITUDE transposition + all cipher models + all periods")
    print("=" * 72)

    lat_perm = keyword_permutation("LATITUDE", 6)
    lat_width = 6
    print(f"LATITUDE permutation: {lat_perm}")

    vig_periods = list(range(2, 98))
    phase1_checked = 0
    phase1_consistent = 0

    for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
        inter = periodic_transposition_decrypt(
            K4, lat_width, lat_perm,
            fill_mode=fill_mode, read_mode=read_mode)

        for cipher_name, check_fn, decrypt_fn in cipher_models:
            for period in vig_periods:
                phase1_checked += 1
                result = check_fn(inter, period)
                if result is not None:
                    phase1_consistent += 1
                    shifts, text, ng = optimize_unconstrained(
                        inter, result["key_shifts"], period,
                        decrypt_fn, rng, num_steps=5000)
                    ah = anchor_hits(text)
                    fs = anchor_alignment_score(text) + language_shape_score(text)
                    key_str = "".join(
                        STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)
                    all_candidates.append({
                        "text": text, "key": key_str, "vig_period": period,
                        "width": lat_width, "permutation": list(lat_perm),
                        "fill_mode": fill_mode, "read_mode": read_mode,
                        "cipher": cipher_name, "keyword": "LATITUDE",
                        "ngram_score": ng, "anchor_hits": ah, "full_score": fs,
                        "constrained": result["constrained"],
                        "phase": "latitude_all_periods",
                    })

    elapsed = time.perf_counter() - t0
    print(f"  Checked {phase1_checked}, found {phase1_consistent} consistent, "
          f"{len(all_candidates)} optimized, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 2: Geographic keyword transpositions + all cipher models
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 2: Geographic keyword transpositions")
    print("=" * 72)

    phase2_checked = 0
    phase2_consistent = 0

    for kw in GEO_KEYWORDS:
        for width in [5, 6, 7, 8, 9, 10]:
            perm = keyword_permutation(kw, width)
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)

                for cipher_name, check_fn, decrypt_fn in cipher_models:
                    for period in range(2, 50):
                        phase2_checked += 1
                        result = check_fn(inter, period)
                        if result is not None:
                            phase2_consistent += 1
                            shifts, text, ng = optimize_unconstrained(
                                inter, result["key_shifts"], period,
                                decrypt_fn, rng, num_steps=3000)
                            ah = anchor_hits(text)
                            fs = anchor_alignment_score(text) + language_shape_score(text)
                            key_str = "".join(
                                STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)
                            all_candidates.append({
                                "text": text, "key": key_str, "vig_period": period,
                                "width": width, "permutation": list(perm),
                                "fill_mode": fill_mode, "read_mode": read_mode,
                                "cipher": cipher_name, "keyword": kw,
                                "ngram_score": ng, "anchor_hits": ah, "full_score": fs,
                                "constrained": result["constrained"],
                                "phase": "geo_keywords",
                            })

        if phase2_checked % 10000 < 300:
            elapsed = time.perf_counter() - t0
            print(f"  {kw}: checked {phase2_checked}, consistent {phase2_consistent}, "
                  f"candidates {len(all_candidates)}, {elapsed:.1f}s")

    elapsed = time.perf_counter() - t0
    print(f"  Total: checked {phase2_checked}, consistent {phase2_consistent}, "
          f"candidates {len(all_candidates)}, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 3: REVERSE cipher order (Vigenere FIRST, then transposition)
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 3: Reverse order — substitution FIRST, then transposition")
    print("=" * 72)

    # If the actual encryption was: plaintext -> Vigenere -> transposition -> ciphertext
    # Then decryption is: ciphertext -> transposition_inverse -> Vigenere_inverse
    # (This is what we tested above.)
    #
    # But if encryption was: plaintext -> transposition -> Vigenere -> ciphertext
    # Then decryption is: ciphertext -> Vigenere_inverse -> transposition_inverse
    # We need to try Vigenere first, then transposition.

    phase3_checked = 0
    phase3_hits = 0

    for kw in ["LATITUDE", "LONGITUDE", "COORDINATES", "POSITION", "PALIMPSEST"]:
        for width in [5, 6, 7, 8]:
            perm = keyword_permutation(kw, width)
            for period in range(2, 50):
                for fill_mode, read_mode in [("row", "column")]:
                    phase3_checked += 1
                    # Try all 26^1 single-shift offsets to find promising Vigenere keys
                    # that when applied first, then transposed, produce anchor matches
                    #
                    # For efficiency: check if ANY Vigenere key of this period could
                    # produce anchors after transposition.
                    # This is harder because the transposition scrambles positions.
                    #
                    # Approach: for each candidate Vigenere key (MCMC), decrypt K4,
                    # then apply transposition inverse, check anchors.

                    # Use constraint approach in reverse:
                    # After transposition, position p in plaintext came from
                    # position trans_map[p] in the Vigenere output.
                    # So: plain[p] = vig_decrypt(cipher[trans_map[p]], key[trans_map[p] % period])
                    # We know plain[p] for anchor positions.

                    # Build the transposition mapping
                    # encrypt: fill by fill_mode, read by read_mode with perm
                    # decrypt: fill by read_mode with perm, read by fill_mode
                    # We need the mapping: for each output position, what input position?

                    # Use a trick: encrypt a numbered sequence to get the mapping
                    numbered = "".join(chr(65 + (i % 26)) for i in range(N))
                    # Actually, let's use indices directly
                    from kryptos.transposition import (
                        existing_cells, fill_order, read_order, column_order, row_order,
                    )
                    from math import ceil

                    cells = set(existing_cells(N, width))
                    f_cells = fill_order(cells, fill_mode, False, False)
                    r_cells = read_order(cells, read_mode, perm, False, False)

                    # Encryption: fill in fill_order, read in read_order
                    # Position i in plaintext -> cell f_cells[i]
                    # Cell at position j in r_cells -> ciphertext[j]
                    # So ciphertext[j] = plaintext[i] where f_cells[i] == r_cells[j]

                    # Build reverse map: for ciphertext position j,
                    # what plaintext position i was it?
                    cell_to_plain = {f_cells[i]: i for i in range(N)}
                    # trans_map[j] = plaintext position that ended up at ciphertext position j
                    enc_map = [cell_to_plain[r_cells[j]] for j in range(N)]
                    # So ciphertext[j] came from plaintext[enc_map[j]]

                    # In the reverse-order model:
                    # plaintext -> transposition -> intermediate -> Vigenere -> ciphertext
                    # So: intermediate[j] = plaintext[enc_map[j]]  (transposition step)
                    # And: ciphertext[j] = vig_encrypt(intermediate[j], key[j % period])
                    # Decryption: intermediate[j] = vig_decrypt(ciphertext[j], key[j % period])
                    #             plaintext[enc_map[j]] = intermediate[j]
                    # So plaintext[p] = intermediate[enc_map_inv[p]]
                    # where enc_map_inv is the inverse: enc_map_inv[enc_map[j]] = j

                    enc_map_inv = [0] * N
                    for j in range(N):
                        enc_map_inv[enc_map[j]] = j

                    # For known plaintext at position p:
                    # intermediate[enc_map_inv[p]] = vig_decrypt(ciphertext[enc_map_inv[p]], key[enc_map_inv[p] % period])
                    # And intermediate must decrypt to plaintext[p]
                    # But intermediate IS the vig decryption result at position enc_map_inv[p]
                    # So: plaintext[p] = intermediate[enc_map_inv[p]]
                    # And: intermediate[j] = (ciphertext[j] - key[j % period]) mod 26
                    # Combined: plaintext[p] = (ciphertext[enc_map_inv[p]] - key[enc_map_inv[p] % period]) mod 26
                    # So: key[enc_map_inv[p] % period] = (ciphertext[enc_map_inv[p]] - plaintext[p]) mod 26

                    slot_reqs: dict[int, set[int]] = {}
                    valid = True
                    for pos, pch in KNOWN_PT.items():
                        j = enc_map_inv[pos]
                        shift = (ord(K4[j]) - ord(pch)) % 26
                        slot = j % period
                        if slot not in slot_reqs:
                            slot_reqs[slot] = set()
                        slot_reqs[slot].add(shift)

                    key_shifts = [-1] * period
                    for slot, shifts_set in slot_reqs.items():
                        if len(shifts_set) != 1:
                            valid = False
                            break
                        key_shifts[slot] = shifts_set.pop()

                    if not valid:
                        continue

                    phase3_hits += 1
                    # Decrypt: Vigenere first on ciphertext, then transposition inverse
                    full_shifts = list(key_shifts)
                    unconstrained = [i for i in range(period) if full_shifts[i] < 0]
                    for slot in unconstrained:
                        full_shifts[slot] = rng.randrange(26)

                    # MCMC on unconstrained slots
                    def eval_reverse(shifts_list):
                        vig_out = "".join(
                            STANDARD_ALPHABET[(ord(K4[j]) - 65 - shifts_list[j % period]) % 26]
                            for j in range(N))
                        plain = periodic_transposition_decrypt(
                            vig_out, width, perm,
                            fill_mode=fill_mode, read_mode=read_mode)
                        return plain, ngram_score(plain)

                    text, score = eval_reverse(full_shifts)
                    best_shifts = list(full_shifts)
                    best_text = text
                    best_score = score

                    for step in range(5000):
                        if not unconstrained:
                            break
                        temp = 3.0 - 2.9 * step / 5000
                        slot = unconstrained[rng.randrange(len(unconstrained))]
                        old = full_shifts[slot]
                        full_shifts[slot] = rng.randrange(26)
                        new_text, new_score = eval_reverse(full_shifts)
                        d = (new_score - score) / max(temp, 0.01)
                        if d > 0 or rng.random() < math.exp(min(d, 50)):
                            score = new_score
                            text = new_text
                            if score > best_score:
                                best_score = score
                                best_shifts = list(full_shifts)
                                best_text = text
                        else:
                            full_shifts[slot] = old

                    ah = anchor_hits(best_text)
                    fs = anchor_alignment_score(best_text) + language_shape_score(best_text)
                    key_str = "".join(
                        STANDARD_ALPHABET[s] if s >= 0 else "?" for s in best_shifts)
                    constrained = sum(1 for s in key_shifts if s >= 0)

                    all_candidates.append({
                        "text": best_text, "key": key_str, "vig_period": period,
                        "width": width, "permutation": list(perm),
                        "fill_mode": fill_mode, "read_mode": read_mode,
                        "cipher": "vigenere_reversed",
                        "keyword": kw,
                        "ngram_score": best_score, "anchor_hits": ah, "full_score": fs,
                        "constrained": constrained,
                        "phase": "reverse_order",
                    })

    elapsed = time.perf_counter() - t0
    print(f"  Checked {phase3_checked}, consistent {phase3_hits}, "
          f"candidates {len(all_candidates)}, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 4: LATITUDE with LONGITUDE-derived Vigenere key
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 4: Keyword-derived Vigenere keys")
    print("=" * 72)

    key_words = [
        "LONGITUDE", "LATITUDE", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
        "COORDINATES", "BERLINCLOCK", "EASTNORTHEAST",
        "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH",
        "SEVENTYSEVENDEGREESMINUTES",
    ]

    for trans_kw in ["LATITUDE", "LONGITUDE", "PALIMPSEST"]:
        for width in [5, 6, 7]:
            perm = keyword_permutation(trans_kw, width)
            for fill_mode, read_mode in [("row", "column")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)

                for vig_kw in key_words:
                    # Use keyword as repeating Vigenere key
                    text = decrypt_vigenere_standard(inter, vig_kw)
                    ah = anchor_hits(text)
                    if ah >= 10:  # At least partial anchor match
                        fs = anchor_alignment_score(text) + language_shape_score(text)
                        all_candidates.append({
                            "text": text, "key": vig_kw,
                            "vig_period": len(vig_kw),
                            "width": width, "permutation": list(perm),
                            "fill_mode": fill_mode, "read_mode": read_mode,
                            "cipher": "vigenere_keyword",
                            "keyword": trans_kw,
                            "ngram_score": ngram_score(text),
                            "anchor_hits": ah, "full_score": fs,
                            "constrained": len(vig_kw),
                            "phase": "keyword_vigenere",
                        })

    elapsed = time.perf_counter() - t0
    print(f"  Keyword Vigenere tests complete, candidates {len(all_candidates)}, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 5: Deep MCMC on top survivors
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 5: Deep MCMC on top survivors")
    print("=" * 72)

    all_candidates.sort(key=lambda x: x["full_score"], reverse=True)

    cipher_decrypt_map = {
        "vigenere": decrypt_vigenere_shifts,
        "beaufort": decrypt_beaufort_shifts,
        "quagmire3": decrypt_quagmire_shifts,
    }

    for idx, cand in enumerate(all_candidates[:100]):
        if cand["phase"] == "reverse_order":
            continue  # Already optimized in place
        if cand["cipher"] == "vigenere_keyword":
            continue  # Fixed key, nothing to optimize

        decrypt_fn = cipher_decrypt_map.get(cand["cipher"], decrypt_vigenere_shifts)
        inter = periodic_transposition_decrypt(
            K4, cand["width"], tuple(cand["permutation"]),
            fill_mode=cand["fill_mode"], read_mode=cand["read_mode"])

        # Reconstruct key_shifts from the stored key
        stored_key = cand["key"]
        base_shifts = [
            ord(ch) - 65 if ch != "?" else -1 for ch in stored_key
        ]

        for chain in range(5):
            shifts, text, ng = optimize_unconstrained(
                inter, base_shifts, cand["vig_period"],
                decrypt_fn, rng, num_steps=8000)
            ah = anchor_hits(text)
            fs = anchor_alignment_score(text) + language_shape_score(text)
            if fs > cand["full_score"]:
                cand["text"] = text
                cand["key"] = "".join(
                    STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)
                cand["ngram_score"] = ng
                cand["anchor_hits"] = ah
                cand["full_score"] = fs

    elapsed = time.perf_counter() - t0
    print(f"  Deep MCMC complete, {elapsed:.1f}s")

    # ===================================================================
    # RESULTS
    # ===================================================================
    all_candidates.sort(key=lambda x: x["full_score"], reverse=True)

    print(f"\n{'=' * 72}")
    print(f"FINAL RESULTS ({elapsed:.1f}s, {len(all_candidates)} candidates)")
    print("=" * 72)

    for i, c in enumerate(all_candidates[:30]):
        bd = build_score_breakdown(c["text"])
        print(f"#{i+1:>2} proj={bd['total']:>3}/1000 "
              f"anch={bd['anchor']:>3} lang={bd['language']:>3} "
              f"full={c['full_score']:>6} ah={c['anchor_hits']:>2} "
              f"cipher={c['cipher']:>12} p={c['vig_period']:>2} "
              f"w={c['width']:>2} kw={c['keyword']}")
        print(f"     {c['text'][:65]}...")

    # Detailed top 10
    print(f"\n{'=' * 72}")
    print("DETAILED TOP 10")
    print("=" * 72)
    for i, c in enumerate(all_candidates[:10]):
        print(f"\n--- #{i+1} (phase: {c['phase']}) ---")
        print(f"Cipher: {c['cipher']}, Period={c['vig_period']}, "
              f"Trans width={c['width']}, Keyword={c['keyword']}")
        print(f"Permutation: {c['permutation']}")
        print(f"Key: {c['key']}")
        print(f"Text: {c['text']}")
        bd = build_score_breakdown(c["text"])
        print(f"Score: {bd['total']}/1000 (anchor={bd['anchor']}, "
              f"lang={bd['language']}, domain={bd['domain']})")
        for clue, start in ANCHORS:
            end = start + len(clue)
            if end <= len(c["text"]):
                seg = c["text"][start:end]
                hits = sum(1 for a, b in zip(seg, clue) if a == b)
                status = "MATCH" if seg == clue else f"{hits}/{len(clue)}"
                print(f"  {clue:>13} at {start}: \"{seg}\" [{status}]")

    # Save
    output = {
        "sweep_type": "latitude_investigation",
        "total_candidates": len(all_candidates),
        "elapsed_seconds": elapsed,
        "phases": {
            "latitude_all_periods": sum(1 for c in all_candidates if c["phase"] == "latitude_all_periods"),
            "geo_keywords": sum(1 for c in all_candidates if c["phase"] == "geo_keywords"),
            "reverse_order": sum(1 for c in all_candidates if c["phase"] == "reverse_order"),
            "keyword_vigenere": sum(1 for c in all_candidates if c["phase"] == "keyword_vigenere"),
        },
        "top_results": [
            {
                "rank": i + 1,
                "text": c["text"],
                "key": c["key"],
                "cipher": c["cipher"],
                "vig_period": c["vig_period"],
                "width": c["width"],
                "permutation": c["permutation"],
                "keyword": c["keyword"],
                "fill_mode": c["fill_mode"],
                "read_mode": c["read_mode"],
                "full_score": c["full_score"],
                "anchor_hits": c["anchor_hits"],
                "constrained": c["constrained"],
                "project_score": build_score_breakdown(c["text"])["total"],
                "phase": c["phase"],
            }
            for i, c in enumerate(all_candidates[:50])
        ],
    }
    with open("runs/latitude_investigation.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/latitude_investigation.json")


if __name__ == "__main__":
    main()
