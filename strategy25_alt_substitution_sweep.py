"""Strategy 25: Beaufort / Quagmire Constraint-First Sweep for K4.

Key insight: the constraint-first framework (fix anchors, sweep transposition
parameters, then optimize free slots) assumes standard Vigenere. But K4 might
use a *different* polyalphabetic cipher. This strategy tests three alternatives:

  A. Beaufort cipher:  C = (K - P) mod 26  =>  K = (C + P) mod 26
     (reciprocal; same tableau read differently)
  B. Quagmire III with KRYPTOS mixed alphabet as the tableau basis.
     Row = KRYPTOS_ALPHABET.index(key_char), then the shifted row is
     KRYPTOS_ALPHABET[row:] + KRYPTOS_ALPHABET[:row].
     Find cipher_char position in that row to get plaintext.
  C. Autokey Vigenere:  key stream = primer + plaintext_so_far.
     Cannot do simple periodic consistency; instead propagate from known
     anchor positions.

For each transposition hypothesis (width 2-20, keyword + random permutations):
  1. Apply transposition inverse to K4
  2. Check Beaufort consistency  (periodic key, same as Vigenere framework)
  3. Check Quagmire III consistency (periodic key, mixed-alphabet tableau)
  4. Check Autokey Vigenere consistency (primer-based, propagated from anchors)
  5. MCMC optimize unconstrained slots with ngram scoring
  6. Report top candidates with full scoring
  7. Save results to runs/alt_substitution_sweep.json
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
    normalize_letters,
)
from kryptos.transposition import (
    periodic_transposition_decrypt, keyword_permutation, identity_permutation,
)

# ---------------------------------------------------------------------------
# Known plaintext (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS_COMPONENT: list[tuple[str, int]] = []
for _c, _d in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS_COMPONENT.append((_c, int(_d["start_index"]) - 1))

COMBINED_ANCHORS: list[tuple[str, int]] = []
for _c, _d in KNOWN_PLAINTEXT_CLUES.items():
    COMBINED_ANCHORS.append((_c, int(_d["start_index"]) - 1))

# All known plaintext positions: position -> required plain char
KNOWN_PT: dict[int, str] = {}
for clue, start in ANCHORS_COMPONENT:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

# Sorted known positions for autokey propagation
KNOWN_POSITIONS_SORTED = sorted(KNOWN_PT.items(), key=lambda x: x[0])

N = len(K4)
CT_INTS = [ord(c) - 65 for c in K4]

# ---------------------------------------------------------------------------
# Quagmire III tableau from KRYPTOS alphabet
# ---------------------------------------------------------------------------
KRYP_TABLEAU: list[str] = [
    KRYPTOS_ALPHABET[i:] + KRYPTOS_ALPHABET[:i] for i in range(26)
]

# Lookup: for standard alphabet, map from char to KRYPTOS_ALPHABET index
KRYP_INDEX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}

# ---------------------------------------------------------------------------
# N-gram scorer (same tables as constraint_first_sweep.py)
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
    for clue, start in ANCHORS_COMPONENT:
        end = start + len(clue)
        if end <= len(text):
            hits += sum(1 for a, b in zip(text[start:end], clue) if a == b)
    return hits


# ===========================================================================
# CIPHER A: Beaufort consistency check
#   Beaufort: C = (K - P) mod 26  =>  K = (C + P) mod 26
#   For a periodic key of length `period`, each position `pos` maps to
#   slot = pos % period. All anchors at the same slot must yield the same K.
# ===========================================================================
def check_beaufort_consistency(intermediate_text: str, period: int) -> dict | None:
    """Check if a Beaufort key of given period can satisfy all known-PT anchors."""
    n = len(intermediate_text)
    slot_requirements: dict[int, set[int]] = {}
    for pos, plain_char in KNOWN_PT.items():
        if pos >= n:
            return None
        ci = ord(intermediate_text[pos]) - 65
        pi = ord(plain_char) - 65
        required_shift = (ci + pi) % 26  # Beaufort: K = (C + P) mod 26
        slot = pos % period
        if slot not in slot_requirements:
            slot_requirements[slot] = set()
        slot_requirements[slot].add(required_shift)

    key_shifts = [-1] * period
    for slot, shifts in slot_requirements.items():
        if len(shifts) != 1:
            return None  # Contradiction
        key_shifts[slot] = shifts.pop()

    constrained = sum(1 for s in key_shifts if s >= 0)
    return {
        "key_shifts": key_shifts,
        "constrained_slots": constrained,
        "total_slots": period,
    }


def decrypt_beaufort_partial(intermediate_text: str, key_shifts: list[int],
                              period: int) -> str:
    """Decrypt with partial Beaufort key.  P = (K - C) mod 26.
    Unconstrained slots (shift=-1) use shift=0 (identity)."""
    result = []
    for i, c in enumerate(intermediate_text):
        k = key_shifts[i % period]
        if k < 0:
            k = 0
        result.append(STANDARD_ALPHABET[(k - (ord(c) - 65)) % 26])
    return "".join(result)


# ===========================================================================
# CIPHER B: Quagmire III consistency check
#   Uses KRYPTOS_ALPHABET as tableau basis.
#   Row for key_char K: KRYPTOS_ALPHABET shifted by KRYPTOS_ALPHABET.index(K)
#   Encryption: PT position in KRYPTOS_ALPHABET -> CT is row[position]
#   Decryption: find CT in row -> position in KRYPTOS_ALPHABET is PT
#   For periodic key, we need a "shift" per slot. We'll define the shift as
#   the KRYPTOS_ALPHABET index of the key character (0..25).
#   Given C and P (both in KRYPTOS_ALPHABET), the key row index k satisfies:
#     row_k = KRYPTOS_ALPHABET[k:] + KRYPTOS_ALPHABET[:k]
#     row_k[KRYP_INDEX[P]] == C
#   which means KRYPTOS_ALPHABET[(KRYP_INDEX[P] + k) % 26] == C
#   so (KRYP_INDEX[P] + k) % 26 == KRYP_INDEX[C]
#   so k = (KRYP_INDEX[C] - KRYP_INDEX[P]) % 26
# ===========================================================================
def check_quagmire3_consistency(intermediate_text: str, period: int) -> dict | None:
    """Check if a Quagmire III key (KRYPTOS alphabet) of given period
    can satisfy all known-PT anchors."""
    n = len(intermediate_text)
    slot_requirements: dict[int, set[int]] = {}
    for pos, plain_char in KNOWN_PT.items():
        if pos >= n:
            return None
        c_char = intermediate_text[pos]
        if c_char not in KRYP_INDEX or plain_char not in KRYP_INDEX:
            return None
        ci = KRYP_INDEX[c_char]
        pi = KRYP_INDEX[plain_char]
        required_k = (ci - pi) % 26  # k = (KRYP_INDEX[C] - KRYP_INDEX[P]) mod 26
        slot = pos % period
        if slot not in slot_requirements:
            slot_requirements[slot] = set()
        slot_requirements[slot].add(required_k)

    key_shifts = [-1] * period
    for slot, shifts in slot_requirements.items():
        if len(shifts) != 1:
            return None
        key_shifts[slot] = shifts.pop()

    constrained = sum(1 for s in key_shifts if s >= 0)
    return {
        "key_shifts": key_shifts,
        "constrained_slots": constrained,
        "total_slots": period,
    }


def decrypt_quagmire3_partial(intermediate_text: str, key_shifts: list[int],
                               period: int) -> str:
    """Decrypt with partial Quagmire III key (KRYPTOS alphabet tableau).
    P = KRYPTOS_ALPHABET[(KRYP_INDEX[C] - k) % 26].
    Unconstrained slots use k=0."""
    result = []
    for i, c in enumerate(intermediate_text):
        k = key_shifts[i % period]
        if k < 0:
            k = 0
        if c in KRYP_INDEX:
            ci = KRYP_INDEX[c]
            result.append(KRYPTOS_ALPHABET[(ci - k) % 26])
        else:
            result.append(c)
    return "".join(result)


# ===========================================================================
# CIPHER C: Autokey Vigenere consistency check
#   Key stream = primer (length L) + plaintext[0], plaintext[1], ...
#   Encryption: C[i] = (P[i] + key_stream[i]) mod 26
#     where key_stream[i] = primer[i] for i < L,
#           key_stream[i] = P[i - L] for i >= L
#   Decryption: P[i] = (C[i] - key_stream[i]) mod 26
#   For known positions, we can propagate backward. If we know P[j], we know
#   key_stream[j] and thus can infer either a primer char or another P char.
#
#   Strategy: for each primer length L (2-12), iterate through known positions
#   and check if the implied primer chars (for positions < L) and the implied
#   earlier-plaintext chars (for positions >= L) are self-consistent.
# ===========================================================================
def check_autokey_consistency(intermediate_text: str, primer_len: int) -> dict | None:
    """Check if an autokey Vigenere with a primer of length `primer_len`
    can satisfy all known-PT anchors.

    Returns a dict with the inferred primer (partial) and any inferred
    plaintext positions, or None if contradictory.
    """
    n = len(intermediate_text)
    # inferred_plain[i] = plaintext char at position i (from anchors + propagation)
    inferred_plain: dict[int, str] = {}
    # inferred_primer[i] = primer char at position i (for 0 <= i < primer_len)
    inferred_primer: dict[int, int] = {}  # index -> shift value (0-25)

    # Seed with all known plaintext
    for pos, ch in KNOWN_PT.items():
        if pos >= n:
            return None
        inferred_plain[pos] = ch

    # Propagation: iterate multiple times to resolve chains
    changed = True
    max_iters = 50
    iteration = 0
    while changed and iteration < max_iters:
        changed = False
        iteration += 1

        for pos in sorted(inferred_plain.keys()):
            p_char = inferred_plain[pos]
            c_char = intermediate_text[pos]
            pi = ord(p_char) - 65
            ci = ord(c_char) - 65
            # key_stream[pos] = (C[pos] - P[pos]) mod 26
            ks = (ci - pi) % 26

            if pos < primer_len:
                # This constrains primer[pos]
                if pos in inferred_primer:
                    if inferred_primer[pos] != ks:
                        return None  # Contradiction in primer
                else:
                    inferred_primer[pos] = ks
                    changed = True
            else:
                # key_stream[pos] = P[pos - primer_len]
                source_pos = pos - primer_len
                source_char = STANDARD_ALPHABET[ks]
                if source_pos in inferred_plain:
                    if inferred_plain[source_pos] != source_char:
                        return None  # Contradiction in propagated plaintext
                else:
                    inferred_plain[source_pos] = source_char
                    changed = True

        # Also propagate forward: if we know P[j] and j + primer_len < n,
        # then key_stream[j + primer_len] = P[j], so we can decrypt pos j+primer_len
        for pos in sorted(inferred_plain.keys()):
            target_pos = pos + primer_len
            if target_pos >= n:
                continue
            if target_pos in inferred_plain:
                continue
            p_char = inferred_plain[pos]
            ks = ord(p_char) - 65  # key_stream[target_pos] = P[pos]
            ci = ord(intermediate_text[target_pos]) - 65
            new_plain = STANDARD_ALPHABET[(ci - ks) % 26]
            inferred_plain[target_pos] = new_plain
            changed = True

        # Forward propagation from known primer slots
        for pslot, pval in list(inferred_primer.items()):
            if pslot >= n:
                continue
            if pslot not in inferred_plain:
                ci = ord(intermediate_text[pslot]) - 65
                new_plain = STANDARD_ALPHABET[(ci - pval) % 26]
                inferred_plain[pslot] = new_plain
                changed = True

    # Verify all original anchors still hold
    for pos, ch in KNOWN_PT.items():
        if pos >= n:
            return None
        if pos in inferred_plain and inferred_plain[pos] != ch:
            return None

    # Build primer (partial)
    primer_shifts = [-1] * primer_len
    for i, val in inferred_primer.items():
        primer_shifts[i] = val

    constrained_primer = sum(1 for s in primer_shifts if s >= 0)
    total_inferred = len(inferred_plain)

    return {
        "primer_shifts": primer_shifts,
        "constrained_primer_slots": constrained_primer,
        "total_primer_slots": primer_len,
        "inferred_plain": inferred_plain,
        "total_inferred_positions": total_inferred,
    }


def decrypt_autokey_partial(intermediate_text: str, primer_shifts: list[int],
                             primer_len: int) -> str:
    """Decrypt with a partial autokey primer. Fill unknown primer slots with 0.
    Sequentially: P[i] = (C[i] - ks[i]) mod 26 where
      ks[i] = primer[i] if i < primer_len else P[i - primer_len]."""
    n = len(intermediate_text)
    primer = [s if s >= 0 else 0 for s in primer_shifts]
    plaintext = [0] * n

    for i in range(n):
        ci = ord(intermediate_text[i]) - 65
        if i < primer_len:
            ks = primer[i]
        else:
            ks = plaintext[i - primer_len]
        plaintext[i] = (ci - ks) % 26

    return "".join(STANDARD_ALPHABET[v] for v in plaintext)


# ===========================================================================
# MCMC optimization for free key slots
# ===========================================================================
def optimize_beaufort_unconstrained(
    intermediate_text: str, key_shifts: list[int], period: int,
    rng: random.Random, num_steps: int = 5000
) -> tuple[list[int], str, float]:
    """MCMC optimize unconstrained Beaufort key slots for English-likeness."""
    shifts = list(key_shifts)
    unconstrained = [i for i in range(period) if shifts[i] < 0]
    for slot in unconstrained:
        shifts[slot] = rng.randrange(26)

    text = decrypt_beaufort_partial(intermediate_text, shifts, period)
    score = ngram_score(text)
    best_shifts, best_text, best_score = list(shifts), text, score

    if not unconstrained:
        return best_shifts, best_text, best_score

    for step in range(num_steps):
        temp = 3.0 - 2.9 * step / num_steps
        slot = unconstrained[rng.randrange(len(unconstrained))]
        old = shifts[slot]
        shifts[slot] = rng.randrange(26)
        new_text = decrypt_beaufort_partial(intermediate_text, shifts, period)
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


def optimize_quagmire3_unconstrained(
    intermediate_text: str, key_shifts: list[int], period: int,
    rng: random.Random, num_steps: int = 5000
) -> tuple[list[int], str, float]:
    """MCMC optimize unconstrained Quagmire III key slots."""
    shifts = list(key_shifts)
    unconstrained = [i for i in range(period) if shifts[i] < 0]
    for slot in unconstrained:
        shifts[slot] = rng.randrange(26)

    text = decrypt_quagmire3_partial(intermediate_text, shifts, period)
    score = ngram_score(text)
    best_shifts, best_text, best_score = list(shifts), text, score

    if not unconstrained:
        return best_shifts, best_text, best_score

    for step in range(num_steps):
        temp = 3.0 - 2.9 * step / num_steps
        slot = unconstrained[rng.randrange(len(unconstrained))]
        old = shifts[slot]
        shifts[slot] = rng.randrange(26)
        new_text = decrypt_quagmire3_partial(intermediate_text, shifts, period)
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


def optimize_autokey_unconstrained(
    intermediate_text: str, primer_shifts: list[int], primer_len: int,
    inferred_plain: dict[int, str],
    rng: random.Random, num_steps: int = 5000
) -> tuple[list[int], str, float]:
    """MCMC optimize unconstrained autokey primer slots.
    The inferred_plain dict constrains additional positions beyond anchors."""
    shifts = list(primer_shifts)
    unconstrained = [i for i in range(primer_len) if shifts[i] < 0]
    for slot in unconstrained:
        shifts[slot] = rng.randrange(26)

    text = decrypt_autokey_partial(intermediate_text, shifts, primer_len)
    score = ngram_score(text)
    best_shifts, best_text, best_score = list(shifts), text, score

    if not unconstrained:
        return best_shifts, best_text, best_score

    for step in range(num_steps):
        temp = 3.0 - 2.9 * step / num_steps
        slot = unconstrained[rng.randrange(len(unconstrained))]
        old = shifts[slot]
        shifts[slot] = rng.randrange(26)
        new_text = decrypt_autokey_partial(intermediate_text, shifts, primer_len)
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
# Transposition generators (same as constraint_first_sweep.py)
# ---------------------------------------------------------------------------
KEYWORD_SEEDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
    "SANBORN", "EAST", "NORTHEAST", "SHADOW", "ILLUSION",
    "EGYPT", "CARTER", "LANGLEY", "TOMB", "LUCENT", "MESSAGE",
]


def generate_permutations(width: int, rng: random.Random,
                          max_perms: int = 150) -> list[tuple[int, ...]]:
    """Generate a diverse set of permutations for a given width."""
    perms: list[tuple[int, ...]] = []
    seen: set[tuple[int, ...]] = set()

    # Identity
    p = identity_permutation(width)
    if p not in seen:
        perms.append(p)
        seen.add(p)

    # Keyword-derived
    for kw in KEYWORD_SEEDS:
        p = keyword_permutation(kw, width)
        if p not in seen:
            perms.append(p)
            seen.add(p)

    # Reversed identity
    p = tuple(range(width - 1, -1, -1))
    if p not in seen:
        perms.append(p)
        seen.add(p)

    # For small widths, enumerate more permutations
    if width <= 6:
        for p in iter_perms(range(width)):
            if p not in seen:
                perms.append(p)
                seen.add(p)
            if len(perms) >= max_perms:
                break
    else:
        # Random permutations
        while len(perms) < max_perms:
            lst = list(range(width))
            rng.shuffle(lst)
            p = tuple(lst)
            if p not in seen:
                perms.append(p)
                seen.add(p)

    return perms


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------
def main():
    rng = random.Random(2025_03_21)
    t0 = time.perf_counter()

    print("=" * 76)
    print("STRATEGY 25: Beaufort / Quagmire Constraint-First Sweep")
    print("Testing alternative substitution ciphers in constraint-first framework")
    print("  A. Beaufort cipher  (periodic key)")
    print("  B. Quagmire III     (KRYPTOS alphabet, periodic key)")
    print("  C. Autokey Vigenere (primer + plaintext-feedback key)")
    print("=" * 76)

    # -----------------------------------------------------------------------
    # PHASE 1: Constraint checks across transposition hypotheses
    # -----------------------------------------------------------------------
    print("\nPHASE 1: Constraint-first search")
    print("For each transposition inverse, check Beaufort / Quag3 / Autokey")
    print("consistency with ALL 24 known-plaintext chars.")
    print("-" * 76)

    beaufort_configs: list[dict] = []
    quagmire3_configs: list[dict] = []
    autokey_configs: list[dict] = []
    total_checked = 0

    widths = list(range(2, 21))       # widths 2-20
    vig_periods = list(range(2, 50))  # periods 2-49
    autokey_primer_lens = list(range(2, 13))  # primer lengths 2-12

    for width in widths:
        n_perms = 200 if width <= 8 else 100 if width <= 15 else 60
        perms = generate_permutations(width, rng, max_perms=n_perms)

        for perm in perms:
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm, fill_mode=fill_mode, read_mode=read_mode)

                # --- Beaufort & Quagmire III (periodic key) ---
                for period in vig_periods:
                    total_checked += 1

                    # Beaufort
                    bres = check_beaufort_consistency(inter, period)
                    if bres is not None:
                        beaufort_configs.append({
                            "width": width,
                            "permutation": list(perm),
                            "fill_mode": fill_mode,
                            "read_mode": read_mode,
                            "period": period,
                            "key_shifts": bres["key_shifts"],
                            "constrained_slots": bres["constrained_slots"],
                            "intermediate": inter,
                            "cipher_type": "beaufort",
                        })

                    # Quagmire III
                    qres = check_quagmire3_consistency(inter, period)
                    if qres is not None:
                        quagmire3_configs.append({
                            "width": width,
                            "permutation": list(perm),
                            "fill_mode": fill_mode,
                            "read_mode": read_mode,
                            "period": period,
                            "key_shifts": qres["key_shifts"],
                            "constrained_slots": qres["constrained_slots"],
                            "intermediate": inter,
                            "cipher_type": "quagmire3",
                        })

                # --- Autokey Vigenere (primer-based) ---
                for primer_len in autokey_primer_lens:
                    total_checked += 1
                    ares = check_autokey_consistency(inter, primer_len)
                    if ares is not None:
                        autokey_configs.append({
                            "width": width,
                            "permutation": list(perm),
                            "fill_mode": fill_mode,
                            "read_mode": read_mode,
                            "primer_len": primer_len,
                            "primer_shifts": ares["primer_shifts"],
                            "constrained_primer_slots": ares["constrained_primer_slots"],
                            "inferred_plain": ares["inferred_plain"],
                            "total_inferred_positions": ares["total_inferred_positions"],
                            "intermediate": inter,
                            "cipher_type": "autokey",
                        })

        if width % 3 == 0 or width <= 4:
            elapsed = time.perf_counter() - t0
            print(f"  width={width:>2}: checked {total_checked:>8} configs | "
                  f"Beaufort={len(beaufort_configs):>5} "
                  f"Quag3={len(quagmire3_configs):>5} "
                  f"Autokey={len(autokey_configs):>5} | "
                  f"{elapsed:.1f}s")

    elapsed = time.perf_counter() - t0
    print(f"\nPhase 1 complete: {total_checked} configs checked")
    print(f"  Beaufort consistent:   {len(beaufort_configs)}")
    print(f"  Quagmire III consistent: {len(quagmire3_configs)}")
    print(f"  Autokey consistent:    {len(autokey_configs)}")
    print(f"  Elapsed: {elapsed:.1f}s")

    # -----------------------------------------------------------------------
    # PHASE 2: MCMC optimization on consistent configs
    # -----------------------------------------------------------------------
    print(f"\n{'=' * 76}")
    print("PHASE 2: MCMC optimization on consistent configs")
    print(f"{'=' * 76}")

    all_candidates: list[dict] = []

    # --- Beaufort ---
    beaufort_configs.sort(key=lambda x: x["constrained_slots"], reverse=True)
    process_limit_b = min(len(beaufort_configs), 2000)
    print(f"\n  Processing {process_limit_b} Beaufort configs...")

    for idx, cfg in enumerate(beaufort_configs[:process_limit_b]):
        shifts, text, ng_score = optimize_beaufort_unconstrained(
            cfg["intermediate"], cfg["key_shifts"], cfg["period"], rng,
            num_steps=3000)

        ah = anchor_hits(text)
        fs = anchor_alignment_score(text) + language_shape_score(text)
        key_str = "".join(STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)

        all_candidates.append({
            "text": text,
            "key": key_str,
            "cipher_type": "beaufort",
            "period": cfg["period"],
            "width": cfg["width"],
            "permutation": cfg["permutation"],
            "fill_mode": cfg["fill_mode"],
            "read_mode": cfg["read_mode"],
            "ngram_score": ng_score,
            "anchor_hits": ah,
            "full_score": fs,
            "constrained_slots": cfg["constrained_slots"],
        })

        if (idx + 1) % 500 == 0:
            elapsed = time.perf_counter() - t0
            best = max(all_candidates, key=lambda x: x["full_score"])
            print(f"    Beaufort {idx+1}/{process_limit_b}: "
                  f"best_full={best['full_score']} ah={best['anchor_hits']} "
                  f"[{best['cipher_type']}] {elapsed:.1f}s")

    # --- Quagmire III ---
    quagmire3_configs.sort(key=lambda x: x["constrained_slots"], reverse=True)
    process_limit_q = min(len(quagmire3_configs), 2000)
    print(f"\n  Processing {process_limit_q} Quagmire III configs...")

    for idx, cfg in enumerate(quagmire3_configs[:process_limit_q]):
        shifts, text, ng_score = optimize_quagmire3_unconstrained(
            cfg["intermediate"], cfg["key_shifts"], cfg["period"], rng,
            num_steps=3000)

        ah = anchor_hits(text)
        fs = anchor_alignment_score(text) + language_shape_score(text)
        key_str = "".join(KRYPTOS_ALPHABET[s] if s >= 0 else "?" for s in shifts)

        all_candidates.append({
            "text": text,
            "key": key_str,
            "cipher_type": "quagmire3",
            "period": cfg["period"],
            "width": cfg["width"],
            "permutation": cfg["permutation"],
            "fill_mode": cfg["fill_mode"],
            "read_mode": cfg["read_mode"],
            "ngram_score": ng_score,
            "anchor_hits": ah,
            "full_score": fs,
            "constrained_slots": cfg["constrained_slots"],
        })

        if (idx + 1) % 500 == 0:
            elapsed = time.perf_counter() - t0
            best = max(all_candidates, key=lambda x: x["full_score"])
            print(f"    Quagmire3 {idx+1}/{process_limit_q}: "
                  f"best_full={best['full_score']} ah={best['anchor_hits']} "
                  f"[{best['cipher_type']}] {elapsed:.1f}s")

    # --- Autokey ---
    autokey_configs.sort(key=lambda x: x["total_inferred_positions"], reverse=True)
    process_limit_a = min(len(autokey_configs), 2000)
    print(f"\n  Processing {process_limit_a} Autokey configs...")

    for idx, cfg in enumerate(autokey_configs[:process_limit_a]):
        shifts, text, ng_score = optimize_autokey_unconstrained(
            cfg["intermediate"], cfg["primer_shifts"], cfg["primer_len"],
            cfg["inferred_plain"], rng, num_steps=3000)

        ah = anchor_hits(text)
        fs = anchor_alignment_score(text) + language_shape_score(text)
        key_str = "".join(STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)

        all_candidates.append({
            "text": text,
            "key": key_str,
            "cipher_type": "autokey",
            "period": cfg["primer_len"],
            "width": cfg["width"],
            "permutation": cfg["permutation"],
            "fill_mode": cfg["fill_mode"],
            "read_mode": cfg["read_mode"],
            "ngram_score": ng_score,
            "anchor_hits": ah,
            "full_score": fs,
            "constrained_slots": cfg.get("constrained_primer_slots", 0),
        })

        if (idx + 1) % 500 == 0:
            elapsed = time.perf_counter() - t0
            best = max(all_candidates, key=lambda x: x["full_score"])
            print(f"    Autokey {idx+1}/{process_limit_a}: "
                  f"best_full={best['full_score']} ah={best['anchor_hits']} "
                  f"[{best['cipher_type']}] {elapsed:.1f}s")

    if not all_candidates:
        elapsed = time.perf_counter() - t0
        print(f"\nNo consistent configs found across any cipher type. ({elapsed:.1f}s)")
        return

    # -----------------------------------------------------------------------
    # PHASE 3: Deep MCMC on top survivors
    # -----------------------------------------------------------------------
    print(f"\n{'=' * 76}")
    print("PHASE 3: Deep MCMC on top 50 survivors")
    print(f"{'=' * 76}")

    all_candidates.sort(key=lambda x: x["full_score"], reverse=True)

    for idx, cand in enumerate(all_candidates[:50]):
        inter = periodic_transposition_decrypt(
            K4, cand["width"], tuple(cand["permutation"]),
            fill_mode=cand["fill_mode"], read_mode=cand["read_mode"])

        for chain in range(5):
            if cand["cipher_type"] == "beaufort":
                shifts, text, ng = optimize_beaufort_unconstrained(
                    inter,
                    cand.get("key_shifts_orig", [-1] * cand["period"]),
                    cand["period"], rng, num_steps=8000)
            elif cand["cipher_type"] == "quagmire3":
                shifts, text, ng = optimize_quagmire3_unconstrained(
                    inter,
                    [-1] * cand["period"],
                    cand["period"], rng, num_steps=8000)
            elif cand["cipher_type"] == "autokey":
                shifts, text, ng = optimize_autokey_unconstrained(
                    inter,
                    [-1] * cand["period"],
                    cand["period"],
                    {},  # No extra constraints in deep phase
                    rng, num_steps=8000)
            else:
                continue

            ah = anchor_hits(text)
            fs = anchor_alignment_score(text) + language_shape_score(text)

            if fs > cand["full_score"]:
                if cand["cipher_type"] == "quagmire3":
                    key_str = "".join(
                        KRYPTOS_ALPHABET[s] if s >= 0 else "?" for s in shifts)
                else:
                    key_str = "".join(
                        STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)
                cand["text"] = text
                cand["key"] = key_str
                cand["ngram_score"] = ng
                cand["anchor_hits"] = ah
                cand["full_score"] = fs

    # -----------------------------------------------------------------------
    # Final results
    # -----------------------------------------------------------------------
    elapsed = time.perf_counter() - t0
    all_candidates.sort(key=lambda x: x["full_score"], reverse=True)

    print(f"\n{'=' * 76}")
    print(f"FINAL RESULTS ({elapsed:.1f}s total, {len(all_candidates)} candidates)")
    print(f"{'=' * 76}\n")

    # Count per cipher type
    type_counts = {}
    for c in all_candidates:
        ct = c["cipher_type"]
        type_counts[ct] = type_counts.get(ct, 0) + 1
    for ct, cnt in sorted(type_counts.items()):
        print(f"  {ct:>12}: {cnt} candidates")
    print()

    # Top 25 summary
    for i, c in enumerate(all_candidates[:25]):
        preview = c["text"][:55] + "..."
        bd = build_score_breakdown(c["text"])
        cipher_label = c["cipher_type"][:7].upper()
        print(f"#{i+1:>2} [{cipher_label:>7}] proj={bd['total']:>3}/1000 "
              f"anch={bd['anchor']:>3} lang={bd['language']:>3} "
              f"full={c['full_score']:>6} ah={c['anchor_hits']:>2} "
              f"p={c['period']:>2} w={c['width']:>2} "
              f"cs={c['constrained_slots']:>2}/{c['period']:>2} "
              f"key={c['key']}")
        print(f"     {preview}")

    # Detailed top 5
    print(f"\n{'=' * 76}")
    print("DETAILED TOP 5")
    print(f"{'=' * 76}")
    for i, c in enumerate(all_candidates[:5]):
        print(f"\n--- #{i+1} [{c['cipher_type'].upper()}] ---")
        print(f"Cipher type: {c['cipher_type']}")
        print(f"Period/Primer: {c['period']}, Transposition width: {c['width']}")
        print(f"Fill={c['fill_mode']}, Read={c['read_mode']}")
        print(f"Permutation: {c['permutation']}")
        print(f"Key: {c['key']}")
        print(f"Text: {c['text']}")
        print(f"Ngram score: {c['ngram_score']:.2f}")
        print(f"Full score: {c['full_score']}, Anchor hits: {c['anchor_hits']}")

        bd = build_score_breakdown(c["text"])
        print(f"Score breakdown: anchor={bd['anchor']} language={bd['language']} "
              f"domain={bd['domain']} entity={bd['entity']} "
              f"structure={bd['structure']} penalty={bd['penalty']} "
              f"total={bd['total']}")

        # Anchor check
        text = c["text"]
        for clue, start in ANCHORS_COMPONENT:
            end = start + len(clue)
            if end <= len(text):
                seg = text[start:end]
                hits = sum(1 for a, b in zip(seg, clue) if a == b)
                status = "MATCH" if seg == clue else f"{hits}/{len(clue)}"
                print(f"  {clue:>13} at {start}: \"{seg}\" [{status}]")

    # -----------------------------------------------------------------------
    # Save results
    # -----------------------------------------------------------------------
    output = {
        "strategy": "25_alt_substitution_sweep",
        "sweep_type": "beaufort_quagmire_autokey_constraint_first",
        "total_checked": total_checked,
        "consistent_counts": {
            "beaufort": len(beaufort_configs),
            "quagmire3": len(quagmire3_configs),
            "autokey": len(autokey_configs),
        },
        "total_candidates": len(all_candidates),
        "elapsed_seconds": round(elapsed, 1),
        "top_results": [
            {
                "rank": i + 1,
                "text": c["text"],
                "key": c["key"],
                "cipher_type": c["cipher_type"],
                "period": c["period"],
                "width": c["width"],
                "permutation": c["permutation"],
                "fill_mode": c["fill_mode"],
                "read_mode": c["read_mode"],
                "full_score": c["full_score"],
                "anchor_hits": c["anchor_hits"],
                "constrained_slots": c["constrained_slots"],
                "project_score": build_score_breakdown(c["text"])["total"],
            }
            for i, c in enumerate(all_candidates[:25])
        ],
    }

    out_path = "runs/alt_substitution_sweep.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
