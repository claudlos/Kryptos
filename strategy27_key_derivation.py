"""Strategy 27: Key Derivation Analysis.

The constraint-first sweep found that the best candidate (772/1000) uses
Vigenere period 28 with key NPHOHACRQZXDQQTBLRQNCPIJRHYF after LATITUDE
transposition. Of the 28 key characters, 24 are fully constrained by the
known plaintext anchors. The 4 unconstrained slots (positions 6, 18, 19, 20)
were optimized by MCMC.

This script investigates whether those 24 constrained key characters derive
from a systematic key generation process:

1. Autokey derivation: Could a short primer + autokey rule produce this key?
2. Running key: Does any substring of K1/K2/K3 plaintext match the key?
3. Rotor/stepping: Does the key show a pattern consistent with a rotor cipher?
4. Key schedule: Is there a mathematical relationship between key positions?
5. Keyword derivation: Can the key be decomposed into repeating keyword(s)?
6. Fibonacci/additive: Are consecutive key differences following a recurrence?
7. Cross-reference with Kryptos-known keywords and phrases
8. Beaufort/reciprocal: Would the key make more sense under a different model?
"""
from __future__ import annotations

import sys
import time
import json
import math
from itertools import product
from collections import Counter

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, K1_PT, K2_PT, K3_PT, ANCHOR_COMPONENT_CLUES,
    STANDARD_ALPHABET, KRYPTOS_ALPHABET, DEFAULT_PRIMERS,
)
from kryptos.common import (
    anchor_alignment_score, language_shape_score, build_score_breakdown,
    decrypt_vigenere_standard, normalize_letters, calculate_ioc,
)
from kryptos.transposition import (
    periodic_transposition_decrypt, keyword_permutation,
)

# ---------------------------------------------------------------------------
# Known plaintext and the best-known key
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _c, _d in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_c, int(_d["start_index"]) - 1))

KNOWN_PT: dict[int, str] = {}
for clue, start in ANCHORS:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

N = len(K4)

# Best config from constraint_first_sweep
BEST_KEY = "NPHOHACRQZXDQQTBLRQNCPIJRHYF"
BEST_PERIOD = 28
BEST_PERM = (1, 5, 3, 0, 2, 4)
BEST_WIDTH = 6

# Constrained key slots (positions where the key char is determined by anchors)
KEY_SHIFTS = [ord(ch) - 65 for ch in BEST_KEY]
CONSTRAINED_SLOTS = set()
UNCONSTRAINED_SLOTS = set()

# Recompute which slots are constrained
lat_inter = periodic_transposition_decrypt(
    K4, BEST_WIDTH, BEST_PERM, fill_mode="row", read_mode="column")

for pos, pch in KNOWN_PT.items():
    shift = (ord(lat_inter[pos]) - ord(pch)) % 26
    slot = pos % BEST_PERIOD
    CONSTRAINED_SLOTS.add(slot)

for i in range(BEST_PERIOD):
    if i not in CONSTRAINED_SLOTS:
        UNCONSTRAINED_SLOTS.add(i)

CONSTRAINED_KEY = "".join(
    BEST_KEY[i] if i in CONSTRAINED_SLOTS else "?" for i in range(BEST_PERIOD))

# Source texts for running key search
SOURCE_TEXTS = {
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K3_PT": K3_PT,
    "K1K2K3": K1_PT + K2_PT + K3_PT,
    "K2K3": K2_PT + K3_PT,
    "KRYPTOS_ALPHA": KRYPTOS_ALPHABET * 10,
}


def main():
    t0 = time.perf_counter()
    findings: list[dict] = []

    print("=" * 72)
    print("STRATEGY 27: Key Derivation Analysis")
    print("=" * 72)
    print(f"\nBest key (p={BEST_PERIOD}): {BEST_KEY}")
    print(f"Constrained:            {CONSTRAINED_KEY}")
    print(f"Constrained slots: {sorted(CONSTRAINED_SLOTS)}")
    print(f"Unconstrained slots: {sorted(UNCONSTRAINED_SLOTS)}")
    print(f"Key as shifts: {KEY_SHIFTS}")

    # ===================================================================
    # TEST 1: Running key search in K1/K2/K3 plaintexts
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 1: Running key substring search")
    print("=" * 72)

    best_running_key_match = 0
    best_running_key_info = None

    for name, source in SOURCE_TEXTS.items():
        source_upper = source.upper()
        for offset in range(len(source_upper) - BEST_PERIOD + 1):
            window = source_upper[offset:offset + BEST_PERIOD]
            if len(window) < BEST_PERIOD:
                continue
            # Count how many constrained positions match
            matches = 0
            for i in CONSTRAINED_SLOTS:
                if i < len(window) and window[i] == BEST_KEY[i]:
                    matches += 1
            if matches > best_running_key_match:
                best_running_key_match = matches
                best_running_key_info = {
                    "source": name, "offset": offset,
                    "window": window, "matches": matches,
                    "total_constrained": len(CONSTRAINED_SLOTS),
                }

    if best_running_key_info:
        print(f"  Best match: {best_running_key_info['matches']}/{best_running_key_info['total_constrained']} "
              f"constrained chars from {best_running_key_info['source']} "
              f"at offset {best_running_key_info['offset']}")
        print(f"  Window: {best_running_key_info['window']}")
        print(f"  Key:    {BEST_KEY}")
        findings.append({"test": "running_key", **best_running_key_info})
    else:
        print("  No matches found.")

    # Also check with Vigenere shift matching (key = shifts from source)
    print("\n  Checking shift-derived running keys...")
    best_shift_match = 0
    best_shift_info = None

    for name, source in SOURCE_TEXTS.items():
        source_upper = source.upper()
        for offset in range(len(source_upper) - BEST_PERIOD + 1):
            window = source_upper[offset:offset + BEST_PERIOD]
            # Convert to shifts
            window_shifts = [ord(ch) - 65 for ch in window if ch in STANDARD_ALPHABET]
            if len(window_shifts) < BEST_PERIOD:
                continue
            matches = sum(1 for i in CONSTRAINED_SLOTS if window_shifts[i] == KEY_SHIFTS[i])
            if matches > best_shift_match:
                best_shift_match = matches
                best_shift_info = {
                    "source": name, "offset": offset,
                    "window": window, "matches": matches,
                }

    if best_shift_info:
        print(f"  Best shift match: {best_shift_info['matches']}/{len(CONSTRAINED_SLOTS)} "
              f"from {best_shift_info['source']} at offset {best_shift_info['offset']}")
        findings.append({"test": "shift_running_key", **best_shift_info})

    # ===================================================================
    # TEST 2: Autokey derivation
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 2: Autokey derivation from short primers")
    print("=" * 72)

    # In autokey Vigenere: key[i] = primer[i] for i < len(primer)
    #                      key[i] = plaintext[i - len(primer)] for i >= len(primer)
    # Check if any short primer (1-8 chars) produces key characters that
    # match the constrained positions.

    best_autokey_match = 0
    best_autokey_info = None

    # We know the plaintext at anchor positions. For autokey,
    # key[i] = plain[i - primer_len] for i >= primer_len.
    # So if i >= primer_len and i is constrained, we need:
    # KEY_SHIFTS[i] = plain_shift[i - primer_len]
    # where plain_shift = ord(plaintext[i - primer_len]) - 65

    # Build known plaintext shifts at all anchor positions
    lat_inter_text = lat_inter  # intermediate after transposition inverse
    known_plain_shifts: dict[int, int] = {}
    for pos, pch in KNOWN_PT.items():
        known_plain_shifts[pos] = ord(pch) - 65

    # For each primer length, check consistency
    for primer_len in range(1, 13):
        # For constrained slots i >= primer_len:
        # KEY_SHIFTS[i] should equal the plaintext shift at position (i - primer_len) in the periodic sense
        # But this is complex because plaintext positions map through the transposition...
        #
        # Simpler approach: treat the KEY itself as an autokey stream.
        # If key = primer + key_derived_from_previous_output, then:
        # key[i] = primer[i] for i < primer_len
        # key[i] = decrypt_output[i - primer_len] for i >= primer_len
        #
        # The decrypt output at position j (in the intermediate text) is:
        # plain[j] = (inter[j] - key[j % period]) mod 26
        #
        # For a full autokey (not periodic), key[i] = plain[i - primer_len]
        # So: key[i] = (inter[i - primer_len] - key[(i - primer_len) % period]) mod 26
        # This creates a dependency chain.

        # For now, just check if any primer of this length makes the first
        # primer_len key characters consistent with the rest via autokey rule.
        # Brute force for small primers.

        if primer_len <= 4:
            # Try all 26^primer_len primers
            for primer_shifts in product(range(26), repeat=primer_len):
                # Build key stream: first primer_len chars = primer
                # Remaining: key[i] = plain[i - primer_len]
                # plain[j] = (inter_shift[j] - key[j]) mod 26
                key_stream = list(primer_shifts)
                valid = True
                matches = 0

                for i in range(BEST_PERIOD):
                    if i < primer_len:
                        # Key is from primer
                        if i in CONSTRAINED_SLOTS and key_stream[i] != KEY_SHIFTS[i]:
                            valid = False
                            break
                        if i in CONSTRAINED_SLOTS:
                            matches += 1
                    else:
                        # key[i] = plain[i - primer_len]
                        # plain[j] = (inter_shift[j] - key[j]) mod 26
                        prev_pos = i - primer_len
                        if prev_pos < len(key_stream):
                            inter_shift = ord(lat_inter[prev_pos]) - 65
                            plain_shift = (inter_shift - key_stream[prev_pos]) % 26
                            key_stream.append(plain_shift)
                            if i in CONSTRAINED_SLOTS:
                                if key_stream[i] != KEY_SHIFTS[i]:
                                    valid = False
                                    break
                                matches += 1
                        else:
                            key_stream.append(0)

                if valid and matches > best_autokey_match:
                    best_autokey_match = matches
                    primer_str = "".join(STANDARD_ALPHABET[s] for s in primer_shifts)
                    key_str = "".join(STANDARD_ALPHABET[s] for s in key_stream[:BEST_PERIOD])
                    best_autokey_info = {
                        "primer": primer_str, "primer_len": primer_len,
                        "matches": matches, "derived_key": key_str,
                    }
        else:
            # For longer primers, seed from constrained positions
            # and check if the autokey rule propagates consistently
            pass

    if best_autokey_info:
        print(f"  Best autokey: {best_autokey_info['matches']}/{len(CONSTRAINED_SLOTS)} "
              f"matches with primer '{best_autokey_info['primer']}' "
              f"(len={best_autokey_info['primer_len']})")
        print(f"  Derived key: {best_autokey_info['derived_key']}")
        print(f"  Actual key:  {BEST_KEY}")
        findings.append({"test": "autokey", **best_autokey_info})
    else:
        print("  No autokey derivation found.")

    # ===================================================================
    # TEST 3: Repeating keyword decomposition
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 3: Repeating keyword decomposition")
    print("=" * 72)

    # Check if the key can be decomposed as a repeating shorter keyword
    for sub_len in range(1, 15):
        if BEST_PERIOD % sub_len != 0:
            continue
        repeats = BEST_PERIOD // sub_len
        sub_key = BEST_KEY[:sub_len]
        reconstructed = (sub_key * repeats)[:BEST_PERIOD]
        matches = sum(1 for i in CONSTRAINED_SLOTS
                      if reconstructed[i] == BEST_KEY[i])
        if matches >= len(CONSTRAINED_SLOTS) * 0.5:
            print(f"  sub_len={sub_len}: '{sub_key}' x {repeats} -> "
                  f"{matches}/{len(CONSTRAINED_SLOTS)} constrained matches")
            findings.append({
                "test": "repeating_keyword", "sub_len": sub_len,
                "sub_key": sub_key, "matches": matches,
            })

    # Also try non-divisor lengths with truncation
    for sub_len in range(2, 15):
        sub_key = BEST_KEY[:sub_len]
        reconstructed = (sub_key * ((BEST_PERIOD // sub_len) + 1))[:BEST_PERIOD]
        matches = sum(1 for i in CONSTRAINED_SLOTS
                      if reconstructed[i] == BEST_KEY[i])
        if matches >= len(CONSTRAINED_SLOTS) * 0.6:
            print(f"  sub_len={sub_len} (non-divisor): '{sub_key}' -> "
                  f"{matches}/{len(CONSTRAINED_SLOTS)} constrained matches")

    # ===================================================================
    # TEST 4: Key difference patterns (additive/Fibonacci)
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 4: Key difference patterns")
    print("=" * 72)

    diffs_1 = [(KEY_SHIFTS[i+1] - KEY_SHIFTS[i]) % 26 for i in range(BEST_PERIOD - 1)]
    diffs_2 = [(KEY_SHIFTS[i+2] - KEY_SHIFTS[i]) % 26 for i in range(BEST_PERIOD - 2)]

    print(f"  Key shifts:     {KEY_SHIFTS}")
    print(f"  1st differences: {diffs_1}")
    print(f"  2nd differences: {diffs_2}")

    # Check for Fibonacci-like: key[i+2] = (key[i] + key[i+1]) mod 26
    fib_matches = sum(1 for i in range(BEST_PERIOD - 2)
                      if (KEY_SHIFTS[i] + KEY_SHIFTS[i+1]) % 26 == KEY_SHIFTS[i+2])
    print(f"  Fibonacci matches: {fib_matches}/{BEST_PERIOD - 2}")

    # Check for linear recurrence: key[i+1] = (a*key[i] + b) mod 26
    best_linear = 0
    best_ab = None
    for a in range(26):
        for b in range(26):
            matches = sum(1 for i in range(BEST_PERIOD - 1)
                          if (a * KEY_SHIFTS[i] + b) % 26 == KEY_SHIFTS[i+1])
            if matches > best_linear:
                best_linear = matches
                best_ab = (a, b)
    print(f"  Best linear recurrence: a={best_ab[0]}, b={best_ab[1]}, "
          f"matches={best_linear}/{BEST_PERIOD - 1}")

    # Check constant difference (Caesar-like progression)
    diff_counts = Counter(diffs_1)
    most_common_diff = diff_counts.most_common(1)[0]
    print(f"  Most common 1st difference: {most_common_diff[0]} "
          f"(appears {most_common_diff[1]}/{BEST_PERIOD - 1} times)")

    findings.append({
        "test": "key_patterns",
        "fibonacci_matches": fib_matches,
        "linear_recurrence": {"a": best_ab[0], "b": best_ab[1], "matches": best_linear},
        "most_common_diff": {"diff": most_common_diff[0], "count": most_common_diff[1]},
    })

    # ===================================================================
    # TEST 5: IC and entropy of the key itself
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 5: Key statistical properties")
    print("=" * 72)

    key_ioc = calculate_ioc(BEST_KEY)
    key_freq = Counter(BEST_KEY)
    key_entropy = -sum(
        (c / BEST_PERIOD) * math.log2(c / BEST_PERIOD)
        for c in key_freq.values()
    )

    print(f"  Key IC: {key_ioc:.4f} (English ~0.065, random ~0.038)")
    print(f"  Key entropy: {key_entropy:.2f} bits (max {math.log2(26):.2f})")
    print(f"  Key frequency: {dict(key_freq.most_common())}")
    print(f"  Unique chars: {len(key_freq)}/{BEST_PERIOD}")

    findings.append({
        "test": "key_stats",
        "ioc": key_ioc,
        "entropy": key_entropy,
        "unique_chars": len(key_freq),
        "frequency": dict(key_freq),
    })

    # ===================================================================
    # TEST 6: Beaufort/reciprocal key interpretation
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 6: Alternative cipher model key interpretation")
    print("=" * 72)

    # Under Beaufort: K = (C + P) mod 26 instead of (C - P) mod 26
    beaufort_shifts = [(ord(lat_inter[pos]) + ord(pch) - 130) % 26
                       for pos, pch in sorted(KNOWN_PT.items())]
    # Reconstruct per-slot
    beau_slot_reqs: dict[int, set[int]] = {}
    for pos, pch in KNOWN_PT.items():
        shift = (ord(lat_inter[pos]) - 65 + ord(pch) - 65) % 26
        slot = pos % BEST_PERIOD
        if slot not in beau_slot_reqs:
            beau_slot_reqs[slot] = set()
        beau_slot_reqs[slot].add(shift)

    beau_consistent = all(len(v) == 1 for v in beau_slot_reqs.values())
    if beau_consistent:
        beau_key = ["?"] * BEST_PERIOD
        for slot, shifts in beau_slot_reqs.items():
            beau_key[slot] = STANDARD_ALPHABET[shifts.pop()]
        beau_key_str = "".join(beau_key)
        print(f"  Beaufort key (consistent): {beau_key_str}")

        # Check if Beaufort key matches any known text
        for name, source in SOURCE_TEXTS.items():
            for offset in range(len(source) - BEST_PERIOD + 1):
                window = source[offset:offset + BEST_PERIOD].upper()
                matches = sum(1 for i in range(BEST_PERIOD)
                              if beau_key[i] != "?" and i < len(window) and window[i] == beau_key[i])
                if matches >= len(CONSTRAINED_SLOTS) * 0.4:
                    print(f"    Beaufort key partial match in {name} at offset {offset}: "
                          f"{matches}/{len(CONSTRAINED_SLOTS)}")

        findings.append({"test": "beaufort_key", "key": beau_key_str, "consistent": True})
    else:
        print("  Beaufort key is NOT consistent for this transposition.")
        findings.append({"test": "beaufort_key", "consistent": False})

    # Quagmire III key
    _KRYP_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}
    quag_slot_reqs: dict[int, set[int]] = {}
    for pos, pch in KNOWN_PT.items():
        cch = lat_inter[pos]
        if cch in _KRYP_IDX and pch in _KRYP_IDX:
            shift = (_KRYP_IDX[cch] - _KRYP_IDX[pch]) % 26
            slot = pos % BEST_PERIOD
            if slot not in quag_slot_reqs:
                quag_slot_reqs[slot] = set()
            quag_slot_reqs[slot].add(shift)

    quag_consistent = all(len(v) == 1 for v in quag_slot_reqs.values())
    if quag_consistent:
        quag_key = ["?"] * BEST_PERIOD
        for slot, shifts in quag_slot_reqs.items():
            quag_key[slot] = KRYPTOS_ALPHABET[shifts.pop()]
        quag_key_str = "".join(quag_key)
        print(f"  Quagmire III key (consistent): {quag_key_str}")
        findings.append({"test": "quagmire_key", "key": quag_key_str, "consistent": True})
    else:
        print("  Quagmire III key is NOT consistent for this transposition.")
        # Show which slots have contradictions
        contradictions = {s: v for s, v in quag_slot_reqs.items() if len(v) > 1}
        print(f"    Contradicting slots: {contradictions}")
        findings.append({"test": "quagmire_key", "consistent": False,
                         "contradictions": {str(k): list(v) for k, v in contradictions.items()}})

    # ===================================================================
    # TEST 7: Key as anagram or permutation of known words
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 7: Key character analysis")
    print("=" * 72)

    constrained_chars = "".join(BEST_KEY[i] for i in sorted(CONSTRAINED_SLOTS))
    print(f"  Constrained chars only: {constrained_chars}")
    print(f"  Sorted: {''.join(sorted(constrained_chars))}")

    # Check if constrained chars are an anagram of any known phrase
    known_phrases = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "EASTNORTHEAST", "BERLINCLOCK", "SHADOW", "ILLUSION",
        "LATITUDE", "LONGITUDE",
    ]
    for phrase in known_phrases:
        if sorted(phrase) == sorted(constrained_chars[:len(phrase)]):
            print(f"  ANAGRAM MATCH: constrained chars are anagram of '{phrase}'!")
            findings.append({"test": "anagram", "phrase": phrase, "match": True})

    # Check letter frequency deviation from English
    eng_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    key_sorted = "".join(ch for ch, _ in key_freq.most_common())
    print(f"  Key letter freq order: {key_sorted}")
    print(f"  English freq order:    {eng_freq[:len(key_sorted)]}")

    # ===================================================================
    # TEST 8: Position-dependent key patterns
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 8: Position-dependent patterns")
    print("=" * 72)

    # Check if key[i] relates to position i
    # key[i] = (a*i + b) mod 26 ?
    best_pos_match = 0
    best_pos_params = None
    for a in range(26):
        for b in range(26):
            matches = sum(1 for i in CONSTRAINED_SLOTS
                          if (a * i + b) % 26 == KEY_SHIFTS[i])
            if matches > best_pos_match:
                best_pos_match = matches
                best_pos_params = (a, b)

    print(f"  Best affine position map: key[i] = ({best_pos_params[0]}*i + {best_pos_params[1]}) mod 26")
    print(f"  Matches: {best_pos_match}/{len(CONSTRAINED_SLOTS)}")

    # key[i] = (a*i^2 + b*i + c) mod 26 ?
    best_quad_match = 0
    best_quad_params = None
    for a in range(26):
        for b in range(26):
            c_candidates: dict[int, int] = {}
            for i in CONSTRAINED_SLOTS:
                needed_c = (KEY_SHIFTS[i] - a * i * i - b * i) % 26
                c_candidates[needed_c] = c_candidates.get(needed_c, 0) + 1
            if c_candidates:
                best_c, count = max(c_candidates.items(), key=lambda x: x[1])
                if count > best_quad_match:
                    best_quad_match = count
                    best_quad_params = (a, b, best_c)

    print(f"  Best quadratic: key[i] = ({best_quad_params[0]}*i^2 + {best_quad_params[1]}*i + {best_quad_params[2]}) mod 26")
    print(f"  Matches: {best_quad_match}/{len(CONSTRAINED_SLOTS)}")

    findings.append({
        "test": "position_patterns",
        "affine": {"a": best_pos_params[0], "b": best_pos_params[1], "matches": best_pos_match},
        "quadratic": {"a": best_quad_params[0], "b": best_quad_params[1],
                      "c": best_quad_params[2], "matches": best_quad_match},
    })

    # ===================================================================
    # TEST 9: Exhaustive unconstrained slot search with English scoring
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("TEST 9: Exhaustive search of unconstrained slots")
    print("=" * 72)

    unc_list = sorted(UNCONSTRAINED_SLOTS)
    print(f"  Unconstrained positions: {unc_list}")
    total_combos = 26 ** len(unc_list)
    print(f"  Total combinations: {total_combos}")

    if total_combos <= 2_000_000:
        # Bigram scoring
        BIGRAM_LOG = {
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
        }
        OTHER = -4.5

        def bigram_score(text):
            return sum(BIGRAM_LOG.get(text[i:i+2], OTHER) for i in range(len(text) - 1))

        base_shifts = list(KEY_SHIFTS)
        inter_ints = [ord(c) - 65 for c in lat_inter]

        best_combo_score = -999999
        best_combo_key = None
        best_combo_text = None
        checked = 0

        for combo in product(range(26), repeat=len(unc_list)):
            for idx, slot in enumerate(unc_list):
                base_shifts[slot] = combo[idx]

            text = "".join(
                STANDARD_ALPHABET[(inter_ints[i] - base_shifts[i % BEST_PERIOD]) % 26]
                for i in range(N))
            sc = bigram_score(text)
            checked += 1

            if sc > best_combo_score:
                best_combo_score = sc
                best_combo_key = "".join(STANDARD_ALPHABET[s] for s in base_shifts)
                best_combo_text = text

            if checked % 100000 == 0:
                print(f"    Checked {checked}/{total_combos}...")

        print(f"\n  Exhaustive search complete: {checked} combinations")
        print(f"  Best key:  {best_combo_key}")
        print(f"  Best text: {best_combo_text}")
        bd = build_score_breakdown(best_combo_text)
        print(f"  Score: {bd['total']}/1000 (anchor={bd['anchor']}, lang={bd['language']})")
        ah = sum(sum(1 for a, b in zip(best_combo_text[s:s+len(c)], c) if a == b)
                 for c, s in ANCHORS if s + len(c) <= N)
        print(f"  Anchor hits: {ah}/24")

        findings.append({
            "test": "exhaustive_unconstrained",
            "combinations": total_combos,
            "best_key": best_combo_key,
            "best_text": best_combo_text,
            "best_bigram_score": best_combo_score,
            "project_score": bd["total"],
            "anchor_hits": ah,
        })
    else:
        print(f"  Too many combinations ({total_combos}), skipping exhaustive search.")

    # ===================================================================
    # SUMMARY
    # ===================================================================
    elapsed = time.perf_counter() - t0
    print(f"\n{'=' * 72}")
    print(f"SUMMARY ({elapsed:.1f}s)")
    print("=" * 72)

    for f in findings:
        test = f["test"]
        if test == "running_key":
            print(f"  Running key: {f['matches']}/{f['total_constrained']} from {f['source']}")
        elif test == "autokey":
            print(f"  Autokey: {f['matches']}/{len(CONSTRAINED_SLOTS)} with primer '{f['primer']}'")
        elif test == "key_stats":
            print(f"  Key IC={f['ioc']:.4f}, entropy={f['entropy']:.2f}, "
                  f"unique={f['unique_chars']}")
        elif test == "key_patterns":
            print(f"  Fibonacci: {f['fibonacci_matches']}, "
                  f"Linear: {f['linear_recurrence']['matches']}, "
                  f"Common diff: {f['most_common_diff']['count']}")
        elif test == "beaufort_key":
            if f["consistent"]:
                print(f"  Beaufort key: {f['key']}")
        elif test == "quagmire_key":
            print(f"  Quagmire III consistent: {f['consistent']}")
        elif test == "position_patterns":
            print(f"  Affine: {f['affine']['matches']}, Quadratic: {f['quadratic']['matches']}")
        elif test == "exhaustive_unconstrained":
            print(f"  Exhaustive: {f['combinations']} combos, "
                  f"best score {f['project_score']}/1000")

    # Save
    output = {
        "strategy": "key_derivation_analysis",
        "best_key": BEST_KEY,
        "constrained_key": CONSTRAINED_KEY,
        "constrained_slots": sorted(CONSTRAINED_SLOTS),
        "unconstrained_slots": sorted(UNCONSTRAINED_SLOTS),
        "elapsed_seconds": elapsed,
        "findings": findings,
    }
    with open("runs/key_derivation_analysis.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/key_derivation_analysis.json")


if __name__ == "__main__":
    main()
