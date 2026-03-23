"""Strategy 40b: Deep Key Pattern Analysis.

The forced Vigenere key at known positions is: BLZCDCYYGCKAZMUYKLGKORNA
Values: [1, 11, 25, 2, 3, 2, 24, 24, 6, 2, 10, 0, 25, 12, 20, 24, 10, 11, 6, 10, 14, 17, 13, 0]

This script deeply analyzes these 24 key values to find:
1. Periodic patterns that work across the gap (pos 21-33 and 63-73)
2. Whether any mathematical function f(position) fits all 24 values
3. Whether Beaufort or Quagmire forced keys show cleaner patterns
4. Polynomial, affine, and recurrence relation fits
5. Whether the key values at known positions match any published text
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kryptos.constants import (
    K4,
    K1_PT,
    K2_PT,
    K3_PT,
    KRYPTOS_ALPHABET,
    STANDARD_ALPHABET,
    ANCHOR_COMPONENT_CLUES,
)

N = len(K4)

ANCHORS_LIST = [(c, int(d["start_index"]) - 1) for c, d in ANCHOR_COMPONENT_CLUES.items()]
KNOWN_PT = {}
for clue, start in ANCHORS_LIST:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch
KNOWN_POSITIONS = sorted(KNOWN_PT.keys())


def forced_key(ct, pt_map, mode="vigenere"):
    """Compute forced key values at known positions under different cipher models."""
    result = {}
    for pos, pch in pt_map.items():
        c = ord(ct[pos]) - 65
        p = ord(pch) - 65
        if mode == "vigenere":
            result[pos] = (c - p) % 26
        elif mode == "beaufort":
            result[pos] = (p - c) % 26
        elif mode == "quagmire":
            ci = KRYPTOS_ALPHABET.index(ct[pos]) if ct[pos] in KRYPTOS_ALPHABET else c
            result[pos] = (ci - p) % 26
    return result


def check_periodicity(key_map, positions):
    """Check which periods are consistent with the forced key values."""
    consistent_periods = []
    for period in range(1, 50):
        ok = True
        # Group positions by their index mod period
        groups = {}
        for pos in positions:
            bucket = pos % period
            if bucket not in groups:
                groups[bucket] = []
            groups[bucket].append(key_map[pos])
        # Check each group has the same value
        for bucket, vals in groups.items():
            if len(set(vals)) > 1:
                ok = False
                break
        if ok:
            consistent_periods.append(period)
    return consistent_periods


def check_affine(key_map, positions):
    """Check if key = (a*pos + b) mod 26 for some (a, b)."""
    solutions = []
    vals = [key_map[p] for p in positions]
    for a in range(26):
        for b in range(26):
            if all((a * p + b) % 26 == key_map[p] for p in positions):
                solutions.append((a, b))
    return solutions


def check_quadratic(key_map, positions):
    """Check if key = (a*pos^2 + b*pos + c) mod 26."""
    solutions = []
    vals = [key_map[p] for p in positions]
    for a in range(26):
        for b in range(26):
            for c in range(26):
                if all((a * p * p + b * p + c) % 26 == key_map[p] for p in positions):
                    solutions.append((a, b, c))
    return solutions


def check_recurrence(key_map, positions, order=2):
    """Check if key values satisfy a linear recurrence of given order.
    For consecutive positions only (within each cluster)."""
    clusters = []
    current = [positions[0]]
    for i in range(1, len(positions)):
        if positions[i] == positions[i-1] + 1:
            current.append(positions[i])
        else:
            clusters.append(current)
            current = [positions[i]]
    clusters.append(current)

    results = {}
    for ci, cluster in enumerate(clusters):
        if len(cluster) <= order:
            continue
        vals = [key_map[p] for p in cluster]
        if order == 2:
            # key[i] = (a * key[i-1] + b * key[i-2]) mod 26
            found = []
            for a in range(26):
                for b in range(26):
                    ok = True
                    for i in range(order, len(vals)):
                        if (a * vals[i-1] + b * vals[i-2]) % 26 != vals[i]:
                            ok = False
                            break
                    if ok:
                        found.append((a, b))
            results[f"cluster_{ci}_pos{cluster[0]}-{cluster[-1]}"] = found
        elif order == 3:
            found = []
            for a in range(26):
                for b in range(26):
                    for c in range(26):
                        ok = True
                        for i in range(order, len(vals)):
                            if (a * vals[i-1] + b * vals[i-2] + c * vals[i-3]) % 26 != vals[i]:
                                ok = False
                                break
                        if ok:
                            found.append((a, b, c))
            results[f"cluster_{ci}_pos{cluster[0]}-{cluster[-1]}"] = found
    return results


def check_running_key_substring(key_map, positions, text, text_name):
    """Check if forced key values appear as a substring of a text at matching offsets."""
    vals = [key_map[p] for p in positions]
    key_letters = [chr(v + 65) for v in vals]

    best_match = 0
    best_offset = -1
    text_alpha = re.sub(r"[^A-Za-z]", "", text).upper()

    for offset in range(len(text_alpha)):
        matches = 0
        for i, pos in enumerate(positions):
            text_pos = offset + pos
            if text_pos < len(text_alpha):
                if ord(text_alpha[text_pos]) - 65 == vals[i]:
                    matches += 1
        if matches > best_match:
            best_match = matches
            best_offset = offset

    return best_match, best_offset


def test_full_key_decrypt(key_shifts):
    """Decrypt K4 with a full 97-shift key and return plaintext + scores."""
    pt = "".join(chr((ord(K4[i]) - 65 - key_shifts[i]) % 26 + 65) for i in range(N))
    # Anchor match
    a = sum(1 for pos, ch in KNOWN_PT.items() if pos < len(pt) and pt[pos] == ch)
    # English scoring
    COMMON = {"TH","HE","IN","ER","AN","RE","ON","AT","EN","ND","TI","ES","OR","TE","OF","ED","IS","IT","AL","AR"}
    bi = sum(1 for i in range(len(pt)-1) if pt[i:i+2] in COMMON)
    # Word detection
    WORDS = {"THE","AND","FOR","ARE","BUT","NOT","YOU","ALL","WAS","ONE","OUR","OUT","HAS","HIS",
             "HOW","MAY","NOW","OLD","SEE","WAY","WHO","DID","GET","HIM","HER","LET","SAY","SHE",
             "TOO","USE","THIS","THAT","WITH","HAVE","FROM","THEY","BEEN","SAID","EACH","WHICH",
             "WILL","ABOUT","THERE","AFTER","BEFORE","BETWEEN","BERLIN","CLOCK","EAST","NORTH",
             "NORTHEAST","WEST","SOUTH","HERE","GUIDE","WORLD"}
    word_hits = sum(len(w) for w in WORDS if w in pt)
    return pt, a, bi, word_hits


def main():
    print("=" * 70)
    print("Strategy 40b: Deep Key Pattern Analysis")
    print("=" * 70)

    results = {}

    for mode in ["vigenere", "beaufort", "quagmire"]:
        print(f"\n{'='*70}")
        print(f"  CIPHER MODEL: {mode.upper()}")
        print(f"{'='*70}")

        key_map = forced_key(K4, KNOWN_PT, mode)
        vals = [key_map[p] for p in KNOWN_POSITIONS]
        letters = "".join(chr(v + 65) for v in vals)

        print(f"\n  Forced key: {letters}")
        print(f"  Values: {vals}")

        # --- Periodicity ---
        consistent = check_periodicity(key_map, KNOWN_POSITIONS)
        short_periods = [p for p in consistent if p <= 30]
        print(f"\n  Consistent periods: {short_periods}")

        # For each short consistent period, show what the key would be
        for period in short_periods:
            if period > 20:
                continue
            key = [None] * period
            for pos in KNOWN_POSITIONS:
                bucket = pos % period
                key[bucket] = key_map[pos]
            key_str = "".join(chr(v + 65) if v is not None else "?" for v in key)
            known_slots = sum(1 for v in key if v is not None)
            unknown_slots = sum(1 for v in key if v is None)
            print(f"    Period {period:2d}: {key_str} ({known_slots} known, {unknown_slots} unknown)")

            # If fully determined, decrypt
            if unknown_slots == 0:
                full_shifts = [key[i % period] for i in range(N)]
                pt, a, bi, wh = test_full_key_decrypt(full_shifts)
                print(f"      -> PT: {pt}")
                print(f"      -> Anchors: {a}/24, Bigrams: {bi}, Words: {wh}")
                if bi > 15 or wh > 20:
                    print(f"      *** INTERESTING CANDIDATE ***")

        # --- Affine ---
        affine_sols = check_affine(key_map, KNOWN_POSITIONS)
        print(f"\n  Affine solutions (key = a*pos + b mod 26): {len(affine_sols)}")
        for a, b in affine_sols[:5]:
            full_shifts = [(a * i + b) % 26 for i in range(N)]
            pt, anch, bi, wh = test_full_key_decrypt(full_shifts)
            print(f"    ({a},{b}): PT={pt[:60]}... anchors={anch} bigrams={bi} words={wh}")

        # --- Quadratic ---
        print(f"\n  Checking quadratic (a*pos^2 + b*pos + c mod 26)...")
        quad_sols = check_quadratic(key_map, KNOWN_POSITIONS)
        print(f"  Quadratic solutions: {len(quad_sols)}")
        for a, b, c in quad_sols[:5]:
            full_shifts = [(a * i * i + b * i + c) % 26 for i in range(N)]
            pt, anch, bi, wh = test_full_key_decrypt(full_shifts)
            print(f"    ({a},{b},{c}): PT={pt[:60]}... anchors={anch} bigrams={bi} words={wh}")

        # --- Recurrence (within consecutive clusters) ---
        print(f"\n  Linear recurrence (order 2) within clusters:")
        rec2 = check_recurrence(key_map, KNOWN_POSITIONS, order=2)
        for cname, sols in rec2.items():
            print(f"    {cname}: {len(sols)} solutions")
            if len(sols) <= 20:
                for s in sols[:5]:
                    print(f"      coefficients: {s}")

        print(f"\n  Linear recurrence (order 3) within clusters:")
        rec3 = check_recurrence(key_map, KNOWN_POSITIONS, order=3)
        for cname, sols in rec3.items():
            print(f"    {cname}: {len(sols)} solutions")

        # --- Cross-cluster recurrence check ---
        # Can we find (a, b) such that key[i] = (a * key[i-1] + b) mod 26
        # works within cluster 1, and then correctly predicts cluster 2?
        print(f"\n  Cross-cluster prediction test:")
        c1_vals = [key_map[p] for p in KNOWN_POSITIONS if p <= 33]
        c2_vals = [key_map[p] for p in KNOWN_POSITIONS if p >= 63]
        c1_pos = [p for p in KNOWN_POSITIONS if p <= 33]
        c2_pos = [p for p in KNOWN_POSITIONS if p >= 63]

        # For each pair (a, b) consistent with cluster 1
        cross_cluster_hits = []
        for a in range(26):
            for b_val in range(26):
                # Check cluster 1 as running recurrence
                ok = True
                for i in range(1, len(c1_vals)):
                    if (a * c1_vals[i-1] + b_val) % 26 != c1_vals[i]:
                        ok = False
                        break
                if not ok:
                    continue

                # Extend the recurrence from end of cluster 1 through the gap to cluster 2
                last = c1_vals[-1]
                current_pos = c1_pos[-1]
                for step in range(c2_pos[0] - c1_pos[-1]):
                    last = (a * last + b_val) % 26
                # Check if it matches cluster 2 start
                predicted = [last]
                for i in range(1, len(c2_vals)):
                    last = (a * last + b_val) % 26
                    predicted.append(last)

                matches = sum(1 for x, y in zip(predicted, c2_vals) if x == y)
                if matches >= 3:
                    cross_cluster_hits.append((a, b_val, matches, predicted))

        if cross_cluster_hits:
            cross_cluster_hits.sort(key=lambda x: x[2], reverse=True)
            print(f"  Found {len(cross_cluster_hits)} cross-cluster recurrences with >= 3 matches:")
            for a, b_val, matches, predicted in cross_cluster_hits[:10]:
                pred_letters = "".join(chr(v + 65) for v in predicted)
                actual_letters = "".join(chr(v + 65) for v in c2_vals)
                print(f"    ({a},{b_val}): predicted {pred_letters} vs actual {actual_letters} ({matches}/{len(c2_vals)} match)")

                # If good match, generate full key and decrypt
                if matches >= 5:
                    full_key = [0] * N
                    # Start from cluster 1 beginning
                    full_key[c1_pos[0]] = c1_vals[0]
                    # Forward from first known
                    v = c1_vals[0]
                    for i in range(c1_pos[0] + 1, N):
                        v = (a * v + b_val) % 26
                        full_key[i] = v
                    # Backward from first known
                    v = c1_vals[0]
                    for i in range(c1_pos[0] - 1, -1, -1):
                        # Reverse: prev = (current - b) * a_inv mod 26
                        if math.gcd(a, 26) == 1:
                            a_inv = pow(a, -1, 26)
                            v = (a_inv * (v - b_val)) % 26
                            full_key[i] = v

                    pt, anch, bi, wh = test_full_key_decrypt(full_key)
                    print(f"      FULL DECRYPT: {pt}")
                    print(f"      Anchors: {anch}/24, Bigrams: {bi}, Words: {wh}")
        else:
            print(f"  No cross-cluster recurrences found with >= 3 matches.")

        # --- Running key from known texts ---
        print(f"\n  Running-key substring search:")
        for name, text in [("K1_PT", K1_PT), ("K2_PT", K2_PT), ("K3_PT", K3_PT),
                           ("KRYPTOS_ALPHA", KRYPTOS_ALPHABET * 10)]:
            hits, offset = check_running_key_substring(key_map, KNOWN_POSITIONS, text, name)
            print(f"    {name}: best {hits}/{len(KNOWN_POSITIONS)} at offset {offset}")

        # Store for final results
        results[mode] = {
            "forced_key": letters,
            "values": vals,
            "consistent_periods": short_periods,
            "affine_solutions": len(affine_sols),
            "quadratic_solutions": len(quad_sols),
        }

    # Save
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "runs", "key_pattern_deep.json",
    )
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
