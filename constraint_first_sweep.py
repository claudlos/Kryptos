"""Constraint-first deep sweep for K4.

Strategy: Fix ALL anchor positions as hard constraints, then work backward
to find cipher parameters (Vigenere key + transposition permutation) that
satisfy those constraints while maximizing English-likeness everywhere else.

Key insight from the previous sweep: no single Vigenere period satisfies
all 4 anchors (EAST, NORTHEAST, BERLIN, CLOCK) simultaneously. This means
either (a) the Vigenere period is wrong, (b) there's a transposition layer,
or (c) the cipher isn't Vigenere at all.

This script:
1. For each transposition hypothesis T (width, permutation):
   - Apply T_inverse to K4 ciphertext
   - For the resulting text, check if a Vigenere key exists that
     makes ALL anchors match at their correct positions
   - If yes: compute the required key at constrained positions,
     then optimize unconstrained positions for English
2. Sweep transposition widths 2-40 with many permutation seeds
3. Try both columnar and route transposition families
4. Combined MCMC on the surviving (transposition, Vigenere) pairs
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
    STANDARD_ALPHABET, DEFAULT_KEYWORDS,
)
from kryptos.common import (
    anchor_alignment_score, language_shape_score, build_score_breakdown,
    build_ranked_candidate, dedupe_ranked_candidates, decrypt_vigenere_standard,
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

N = len(K4)
CT_INTS = [ord(c) - 65 for c in K4]

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
    for clue, start in ANCHORS_COMPONENT:
        end = start + len(clue)
        if end <= len(text):
            hits += sum(1 for a, b in zip(text[start:end], clue) if a == b)
    return hits

# ---------------------------------------------------------------------------
# Core: Check if a Vigenere key of period p can satisfy ALL anchors
# after a transposition has been applied
# ---------------------------------------------------------------------------
def check_vigenere_consistency(intermediate_text: str, period: int) -> dict | None:
    """Given intermediate text (after transposition inverse), check if
    a Vigenere key of the given period can produce ALL known plaintext
    at the correct positions.

    Returns the key (with -1 for unconstrained slots) or None if inconsistent.
    """
    n = len(intermediate_text)
    # For each key slot (0..period-1), collect required shift values
    slot_requirements: dict[int, set[int]] = {}
    for pos, plain_char in KNOWN_PT.items():
        if pos >= n:
            return None
        ci = ord(intermediate_text[pos]) - 65
        pi = ord(plain_char) - 65
        required_shift = (ci - pi) % 26
        slot = pos % period
        if slot not in slot_requirements:
            slot_requirements[slot] = set()
        slot_requirements[slot].add(required_shift)

    # Check consistency: each slot must have exactly ONE required shift
    key_shifts = [-1] * period
    for slot, shifts in slot_requirements.items():
        if len(shifts) != 1:
            return None  # Contradiction!
        key_shifts[slot] = shifts.pop()

    # Count how many slots are constrained
    constrained = sum(1 for s in key_shifts if s >= 0)

    return {
        "key_shifts": key_shifts,
        "constrained_slots": constrained,
        "total_slots": period,
    }


def decrypt_with_partial_key(intermediate_text: str, key_shifts: list[int],
                              period: int) -> str:
    """Decrypt intermediate text with a partial Vigenere key.
    Unconstrained positions (shift=-1) get shift=0 (identity).
    """
    result = []
    for i, c in enumerate(intermediate_text):
        shift = key_shifts[i % period]
        if shift < 0:
            shift = 0
        result.append(STANDARD_ALPHABET[(ord(c) - 65 - shift) % 26])
    return "".join(result)


def optimize_unconstrained(intermediate_text: str, key_shifts: list[int],
                            period: int, rng: random.Random,
                            num_steps: int = 5000) -> tuple[list[int], str, float]:
    """MCMC optimize the unconstrained key slots for English-likeness."""
    shifts = list(key_shifts)
    n = len(intermediate_text)

    # Initialize unconstrained slots randomly
    unconstrained = [i for i in range(period) if shifts[i] < 0]
    for slot in unconstrained:
        shifts[slot] = rng.randrange(26)

    text = decrypt_with_partial_key(intermediate_text, shifts, period)
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
        new_text = decrypt_with_partial_key(intermediate_text, shifts, period)
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
# Transposition generators
# ---------------------------------------------------------------------------
def generate_permutations(width: int, rng: random.Random,
                          max_perms: int = 200) -> list[tuple[int, ...]]:
    """Generate a diverse set of permutations for a given width."""
    perms: list[tuple[int, ...]] = []
    seen: set[tuple[int, ...]] = set()

    # Identity
    p = identity_permutation(width)
    if p not in seen:
        perms.append(p)
        seen.add(p)

    # Keyword-derived
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
               "SANBORN", "EAST", "NORTHEAST", "SHADOW", "ILLUSION",
               "EGYPT", "CARTER", "LANGLEY", "TOMB", "LUCENT", "MESSAGE"]:
        p = keyword_permutation(kw, width)
        if p not in seen:
            perms.append(p)
            seen.add(p)

    # Reversed identity
    p = tuple(range(width - 1, -1, -1))
    if p not in seen:
        perms.append(p)
        seen.add(p)

    # For small widths, add all permutations
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
    rng = random.Random(2026_03_21)
    t0 = time.perf_counter()

    # Phase 1: Constraint-first transposition + Vigenere enumeration
    # For each transposition (width, perm), check ALL Vigenere periods
    # for anchor consistency.
    print("=" * 72)
    print("PHASE 1: Constraint-first search")
    print("For each transposition inverse, find Vigenere periods where")
    print("ALL 24 known-plaintext chars are simultaneously consistent.")
    print("=" * 72)

    consistent_configs: list[dict] = []
    total_checked = 0
    widths = list(range(2, 41))  # widths 2-40
    vig_periods = list(range(2, 50))  # periods 2-49

    for width in widths:
        n_perms = 300 if width <= 8 else 150 if width <= 15 else 80
        perms = generate_permutations(width, rng, max_perms=n_perms)

        for perm in perms:
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm, fill_mode=fill_mode, read_mode=read_mode)

                for period in vig_periods:
                    total_checked += 1
                    result = check_vigenere_consistency(inter, period)
                    if result is not None:
                        consistent_configs.append({
                            "width": width,
                            "permutation": list(perm),
                            "fill_mode": fill_mode,
                            "read_mode": read_mode,
                            "vig_period": period,
                            "key_shifts": result["key_shifts"],
                            "constrained_slots": result["constrained_slots"],
                            "intermediate": inter,
                        })

        if (width % 5 == 0 or width <= 5) and width > 1:
            elapsed = time.perf_counter() - t0
            print(f"  width={width:>2}: checked {total_checked:>8} configs, "
                  f"found {len(consistent_configs):>5} consistent, "
                  f"elapsed={elapsed:.1f}s")

    elapsed = time.perf_counter() - t0
    print(f"\nPhase 1 complete: {total_checked} configs checked, "
          f"{len(consistent_configs)} consistent, {elapsed:.1f}s")

    if not consistent_configs:
        print("NO consistent configs found. Exiting.")
        return

    # Phase 2: Optimize unconstrained key slots via MCMC
    print(f"\n{'=' * 72}")
    print("PHASE 2: Optimize unconstrained Vigenere key slots")
    print(f"Running MCMC on {len(consistent_configs)} consistent configs")
    print(f"{'=' * 72}")

    all_candidates: list[dict] = []

    # Sort by constrained_slots descending (more constrained = stronger signal)
    consistent_configs.sort(key=lambda x: x["constrained_slots"], reverse=True)

    # Process top configs (cap to avoid infinite runtime)
    process_limit = min(len(consistent_configs), 3000)
    for idx, cfg in enumerate(consistent_configs[:process_limit]):
        shifts, text, ng_score = optimize_unconstrained(
            cfg["intermediate"], cfg["key_shifts"], cfg["vig_period"], rng,
            num_steps=3000)

        ah = anchor_hits(text)
        fs = anchor_alignment_score(text) + language_shape_score(text)
        key_str = "".join(STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)

        all_candidates.append({
            "text": text,
            "key": key_str,
            "vig_period": cfg["vig_period"],
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
            print(f"  {idx+1}/{process_limit}: best_full={best['full_score']} "
                  f"anchors={best['anchor_hits']} "
                  f"p={best['vig_period']} w={best['width']} "
                  f"elapsed={elapsed:.1f}s")

    # Phase 3: Deep MCMC on top survivors
    print(f"\n{'=' * 72}")
    print("PHASE 3: Deep MCMC on top survivors")
    print(f"{'=' * 72}")

    # Sort by full_score
    all_candidates.sort(key=lambda x: x["full_score"], reverse=True)

    # For top 50, run deeper optimization
    for idx, cand in enumerate(all_candidates[:50]):
        for chain in range(5):
            shifts, text, ng = optimize_unconstrained(
                periodic_transposition_decrypt(
                    K4, cand["width"], tuple(cand["permutation"]),
                    fill_mode=cand["fill_mode"], read_mode=cand["read_mode"]),
                cand["key_shifts"] if "key_shifts" in cand else [-1] * cand["vig_period"],
                cand["vig_period"], rng, num_steps=10000)

            ah = anchor_hits(text)
            fs = anchor_alignment_score(text) + language_shape_score(text)
            key_str = "".join(STANDARD_ALPHABET[s] if s >= 0 else "?" for s in shifts)

            if fs > cand["full_score"]:
                cand["text"] = text
                cand["key"] = key_str
                cand["ngram_score"] = ng
                cand["anchor_hits"] = ah
                cand["full_score"] = fs

    # Final results
    elapsed = time.perf_counter() - t0
    all_candidates.sort(key=lambda x: x["full_score"], reverse=True)

    print(f"\n{'=' * 72}")
    print(f"FINAL RESULTS ({elapsed:.1f}s total, {len(all_candidates)} candidates)")
    print(f"{'=' * 72}\n")

    for i, c in enumerate(all_candidates[:25]):
        preview = c["text"][:60] + "..."
        bd = build_score_breakdown(c["text"])
        print(f"#{i+1:>2} proj={bd['total']:>3}/1000 "
              f"anch={bd['anchor']:>3} lang={bd['language']:>3} "
              f"full={c['full_score']:>6} ah={c['anchor_hits']:>2} "
              f"p={c['vig_period']:>2} w={c['width']:>2} "
              f"cs={c['constrained_slots']:>2}/{c['vig_period']:>2} "
              f"key={c['key']}")
        print(f"     {preview}")

    # Detailed look at top 5
    print(f"\n{'=' * 72}")
    print("DETAILED TOP 5")
    print(f"{'=' * 72}")
    for i, c in enumerate(all_candidates[:5]):
        print(f"\n--- #{i+1} ---")
        print(f"Vigenere period={c['vig_period']}, Transposition width={c['width']}")
        print(f"Fill={c['fill_mode']}, Read={c['read_mode']}")
        print(f"Permutation: {c['permutation']}")
        print(f"Key: {c['key']}")
        print(f"Text: {c['text']}")
        # Anchor check
        text = c["text"]
        for clue, start in ANCHORS_COMPONENT:
            end = start + len(clue)
            if end <= len(text):
                seg = text[start:end]
                hits = sum(1 for a, b in zip(seg, clue) if a == b)
                status = "MATCH" if seg == clue else f"{hits}/{len(clue)}"
                print(f"  {clue:>13} at {start}: \"{seg}\" [{status}]")

    # Save results
    output = {
        "sweep_type": "constraint_first_deep",
        "total_checked": total_checked,
        "total_consistent": len(consistent_configs),
        "total_candidates": len(all_candidates),
        "elapsed_seconds": elapsed,
        "top_results": [
            {
                "rank": i + 1,
                "text": c["text"],
                "key": c["key"],
                "vig_period": c["vig_period"],
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
    with open("runs/constraint_first_deep.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/constraint_first_deep.json")


if __name__ == "__main__":
    main()
