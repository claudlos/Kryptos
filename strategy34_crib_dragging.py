#!/usr/bin/env python3
"""Strategy 34 – Crib-Dragging Autocorrelation.

Slides the 24 known plaintext characters against K4 at various offsets
and cipher models to detect patterns that reveal the cipher type.

Methods:
  1. Vigenere shift autocorrelation
  2. Beaufort shift autocorrelation
  3. Difference autocorrelation (shift coincidences by period)
  4. Mutual IC per candidate period
  5. Kasiski examination (repeated n-grams)
  6. Phi test (sum of column ICs)
"""

from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter, defaultdict
from itertools import combinations

sys.path.insert(0, ".")

from kryptos.constants import K4, ANCHOR_COMPONENT_CLUES, STANDARD_ALPHABET

# ---------------------------------------------------------------------------
# Build known plaintext mapping: {0-indexed ciphertext position -> plaintext char}
# ---------------------------------------------------------------------------
KNOWN: dict[int, str] = {}
for clue_text, details in ANCHOR_COMPONENT_CLUES.items():
    start_0 = int(details["start_index"]) - 1  # convert 1-indexed to 0-indexed
    for i, ch in enumerate(clue_text):
        KNOWN[start_0 + i] = ch

N = len(K4)  # 97
KNOWN_POSITIONS = sorted(KNOWN.keys())
print(f"K4 length: {N}")
print(f"Known plaintext positions (0-indexed): {KNOWN_POSITIONS}")
print(f"Total known chars: {len(KNOWN_POSITIONS)}")
print(f"Known pairs: " + "".join(
    f"{K4[p]}->{KNOWN[p]}" + ("  " if (i + 1) % 8 else "\n              ")
    for i, p in enumerate(KNOWN_POSITIONS)
))
print()

# English letter frequencies (standard)
ENGLISH_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074,
}

RESULTS: dict = {
    "strategy": 34,
    "name": "Crib-Dragging Autocorrelation",
    "k4": K4,
    "known_positions": KNOWN_POSITIONS,
    "methods": {},
}


def ord26(ch: str) -> int:
    return ord(ch) - ord('A')


# ===================================================================
# 1. VIGENERE SHIFT AUTOCORRELATION
# ===================================================================
print("=" * 72)
print("METHOD 1: VIGENERE SHIFT AUTOCORRELATION")
print("  shift = (C - P) % 26 at each known position")
print("=" * 72)

# Compute Vigenere shifts at the known positions
vig_shifts: dict[int, int] = {}
for pos in KNOWN_POSITIONS:
    c = ord26(K4[pos])
    p = ord26(KNOWN[pos])
    vig_shifts[pos] = (c - p) % 26

print("Position -> Cipher -> Plain -> Vigenere Shift (letter)")
for pos in KNOWN_POSITIONS:
    s = vig_shifts[pos]
    print(f"  {pos:3d}  {K4[pos]} -> {KNOWN[pos]}  shift={s:2d} ({STANDARD_ALPHABET[s]})")

# For each offset d, count how many pairs of known positions have equal shifts
# when both pos and pos+d map to known positions (self-correlation of shift stream)
# Alternative: just count the most common shift value among all known positions
# shifted by d in the ciphertext.

# Actually - we compute: for offset d in 0..N-1, look at all known positions p.
# If p+d is also within K4, compute shift at position p+d under the hypothesis
# that position p+d decrypts the same way. But we only know the cipher at p+d,
# not the plain. So instead: measure coincidences among the known shifts.

# Better approach: among the known shifts, count pairs with equal shift values
# where positions differ by a multiple of candidate period p.
# This is really method 3. Let's do the simpler version first:

# Count the most frequent shift value
shift_counts = Counter(vig_shifts.values())
print(f"\nVigenere shift distribution:")
for s, cnt in shift_counts.most_common():
    print(f"  shift {s:2d} ({STANDARD_ALPHABET[s]}): {cnt} occurrences")

# Autocorrelation: for each lag d, count positions where shift[pos] == shift[pos+d]
# (both must be known positions)
vig_autocorr: dict[int, int] = {}
for d in range(1, N):
    matches = 0
    total = 0
    for pos in KNOWN_POSITIONS:
        if (pos + d) in vig_shifts:
            total += 1
            if vig_shifts[pos] == vig_shifts[pos + d]:
                matches += 1
    if total > 0:
        vig_autocorr[d] = matches

print(f"\nVigenere shift autocorrelation (lag -> matching pairs):")
vig_sorted = sorted(vig_autocorr.items(), key=lambda x: (-x[1], x[0]))
for d, m in vig_sorted[:20]:
    print(f"  lag {d:3d}: {m} matches")

# Extract top candidate periods from high-autocorrelation lags
vig_top_lags = [d for d, m in vig_sorted[:10]]

RESULTS["methods"]["vigenere_shift_autocorrelation"] = {
    "shifts": {str(p): s for p, s in vig_shifts.items()},
    "shift_distribution": {STANDARD_ALPHABET[s]: cnt for s, cnt in shift_counts.most_common()},
    "autocorrelation_top20": [{"lag": d, "matches": m} for d, m in vig_sorted[:20]],
    "top_lags": vig_top_lags,
}


# ===================================================================
# 2. BEAUFORT SHIFT AUTOCORRELATION
# ===================================================================
print("\n" + "=" * 72)
print("METHOD 2: BEAUFORT SHIFT AUTOCORRELATION")
print("  shift = (C + P) % 26 at each known position")
print("=" * 72)

beau_shifts: dict[int, int] = {}
for pos in KNOWN_POSITIONS:
    c = ord26(K4[pos])
    p = ord26(KNOWN[pos])
    beau_shifts[pos] = (c + p) % 26

print("Position -> Cipher -> Plain -> Beaufort Shift (letter)")
for pos in KNOWN_POSITIONS:
    s = beau_shifts[pos]
    print(f"  {pos:3d}  {K4[pos]} -> {KNOWN[pos]}  shift={s:2d} ({STANDARD_ALPHABET[s]})")

beau_shift_counts = Counter(beau_shifts.values())
print(f"\nBeaufort shift distribution:")
for s, cnt in beau_shift_counts.most_common():
    print(f"  shift {s:2d} ({STANDARD_ALPHABET[s]}): {cnt} occurrences")

beau_autocorr: dict[int, int] = {}
for d in range(1, N):
    matches = 0
    for pos in KNOWN_POSITIONS:
        if (pos + d) in beau_shifts:
            if beau_shifts[pos] == beau_shifts[pos + d]:
                matches += 1
    if matches > 0:
        beau_autocorr[d] = matches

beau_sorted = sorted(beau_autocorr.items(), key=lambda x: (-x[1], x[0]))
print(f"\nBeaufort shift autocorrelation (lag -> matching pairs):")
for d, m in beau_sorted[:20]:
    print(f"  lag {d:3d}: {m} matches")

beau_top_lags = [d for d, m in beau_sorted[:10]]

RESULTS["methods"]["beaufort_shift_autocorrelation"] = {
    "shifts": {str(p): s for p, s in beau_shifts.items()},
    "shift_distribution": {STANDARD_ALPHABET[s]: cnt for s, cnt in beau_shift_counts.most_common()},
    "autocorrelation_top20": [{"lag": d, "matches": m} for d, m in beau_sorted[:20]],
    "top_lags": beau_top_lags,
}


# ===================================================================
# 3. DIFFERENCE AUTOCORRELATION
# ===================================================================
print("\n" + "=" * 72)
print("METHOD 3: DIFFERENCE AUTOCORRELATION")
print("  For each candidate period p (1-50), count pairs (i,j) of known")
print("  positions where (i-j)%p==0 AND shift_i == shift_j (Vigenere model)")
print("=" * 72)


def difference_autocorrelation(shifts: dict[int, int], model_name: str) -> list[tuple[int, float]]:
    """Count coincidences for each candidate period."""
    period_scores: dict[int, tuple[int, int]] = {}  # period -> (matches, total)

    for p in range(1, 51):
        matches = 0
        total = 0
        for i, j in combinations(KNOWN_POSITIONS, 2):
            if (i - j) % p == 0:
                total += 1
                if shifts[i] == shifts[j]:
                    matches += 1
        if total > 0:
            period_scores[p] = (matches, total)

    # Normalize: score = matches / total (ratio of coincidences)
    results = []
    for p in range(1, 51):
        if p in period_scores:
            m, t = period_scores[p]
            ratio = m / t if t > 0 else 0
            results.append((p, ratio, m, t))

    results.sort(key=lambda x: -x[1])
    return results


print("\n--- Vigenere model ---")
vig_diff = difference_autocorrelation(vig_shifts, "Vigenere")
print(f"{'Period':>6} {'Ratio':>8} {'Matches':>8} {'Total':>6}")
for p, ratio, m, t in vig_diff[:15]:
    print(f"  {p:4d}  {ratio:8.4f}  {m:6d}  {t:6d}")

print("\n--- Beaufort model ---")
beau_diff = difference_autocorrelation(beau_shifts, "Beaufort")
print(f"{'Period':>6} {'Ratio':>8} {'Matches':>8} {'Total':>6}")
for p, ratio, m, t in beau_diff[:15]:
    print(f"  {p:4d}  {ratio:8.4f}  {m:6d}  {t:6d}")

RESULTS["methods"]["difference_autocorrelation"] = {
    "vigenere_top15": [
        {"period": p, "ratio": round(ratio, 6), "matches": m, "total": t}
        for p, ratio, m, t in vig_diff[:15]
    ],
    "beaufort_top15": [
        {"period": p, "ratio": round(ratio, 6), "matches": m, "total": t}
        for p, ratio, m, t in beau_diff[:15]
    ],
}


# ===================================================================
# 4. MUTUAL IC
# ===================================================================
print("\n" + "=" * 72)
print("METHOD 4: MUTUAL IC (Index of Coincidence per period)")
print("  For each period p, split K4 into p streams.")
print("  Compute IC of each stream and average.")
print("=" * 72)


def compute_ic(text: str) -> float:
    """Compute the Index of Coincidence of a text."""
    n = len(text)
    if n <= 1:
        return 0.0
    counts = Counter(text)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def mutual_ic_with_english(text: str) -> float:
    """Compute mutual IC between text frequencies and English frequencies."""
    n = len(text)
    if n == 0:
        return 0.0
    counts = Counter(text)
    total = 0.0
    for ch in STANDARD_ALPHABET:
        fi = counts.get(ch, 0) / n
        total += fi * ENGLISH_FREQ.get(ch, 0)
    return total


ic_results: list[tuple[int, float, float]] = []  # (period, avg_ic, avg_mutual_ic)
for p in range(1, 51):
    streams = ['' for _ in range(p)]
    for i, ch in enumerate(K4):
        streams[i % p] += ch

    ics = [compute_ic(s) for s in streams]
    mutual_ics = [mutual_ic_with_english(s) for s in streams]

    avg_ic = sum(ics) / len(ics) if ics else 0
    avg_mutual = sum(mutual_ics) / len(mutual_ics) if mutual_ics else 0
    ic_results.append((p, avg_ic, avg_mutual))

# Sort by avg IC descending
ic_by_ic = sorted(ic_results, key=lambda x: -x[1])
ic_by_mutual = sorted(ic_results, key=lambda x: -x[2])

# English IC is ~0.0667, random is ~0.0385
print(f"\nOverall K4 IC: {compute_ic(K4):.6f}")
print(f"Expected English IC: 0.0667, Random IC: 0.0385")

print(f"\nTop 10 periods by average column IC:")
print(f"{'Period':>6} {'Avg IC':>10} {'Avg Mutual IC':>14}")
for p, aic, ami in ic_by_ic[:10]:
    print(f"  {p:4d}  {aic:10.6f}  {ami:14.6f}")

print(f"\nTop 10 periods by average mutual IC with English:")
print(f"{'Period':>6} {'Avg IC':>10} {'Avg Mutual IC':>14}")
for p, aic, ami in ic_by_mutual[:10]:
    print(f"  {p:4d}  {aic:10.6f}  {ami:14.6f}")

RESULTS["methods"]["mutual_ic"] = {
    "overall_k4_ic": round(compute_ic(K4), 6),
    "top10_by_column_ic": [
        {"period": p, "avg_ic": round(aic, 6), "avg_mutual_ic": round(ami, 6)}
        for p, aic, ami in ic_by_ic[:10]
    ],
    "top10_by_mutual_ic": [
        {"period": p, "avg_ic": round(aic, 6), "avg_mutual_ic": round(ami, 6)}
        for p, aic, ami in ic_by_mutual[:10]
    ],
}


# ===================================================================
# 5. KASISKI EXAMINATION
# ===================================================================
print("\n" + "=" * 72)
print("METHOD 5: KASISKI EXAMINATION")
print("  Find repeated bigrams/trigrams in K4, compute GCD of distances")
print("=" * 72)


def find_repeated_ngrams(text: str, n: int) -> dict[str, list[int]]:
    """Find all n-grams that appear more than once, with their positions."""
    ngrams: dict[str, list[int]] = defaultdict(list)
    for i in range(len(text) - n + 1):
        gram = text[i:i + n]
        ngrams[gram].append(i)
    return {gram: positions for gram, positions in ngrams.items() if len(positions) > 1}


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def gcd_of_list(lst: list[int]) -> int:
    result = lst[0]
    for x in lst[1:]:
        result = gcd(result, x)
    return result


# Find repeated bigrams, trigrams, and 4-grams
all_distances: list[int] = []
kasiski_data: dict[str, list] = {}

for n in [2, 3, 4]:
    repeats = find_repeated_ngrams(K4, n)
    gram_name = {2: "bigrams", 3: "trigrams", 4: "4-grams"}[n]
    print(f"\nRepeated {gram_name}:")

    gram_info = []
    for gram, positions in sorted(repeats.items()):
        distances = []
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                d = positions[j] - positions[i]
                distances.append(d)
                all_distances.append(d)

        g = gcd_of_list(distances) if len(distances) >= 1 else 0
        print(f"  {gram}: positions={positions}, distances={distances}, GCD={g}")
        gram_info.append({
            "ngram": gram,
            "positions": positions,
            "distances": distances,
            "gcd": g,
        })

    kasiski_data[gram_name] = gram_info

# Compute factor frequencies across all distances
if all_distances:
    factor_counts: Counter = Counter()
    for d in all_distances:
        if d > 0:
            for f in range(2, min(d + 1, 51)):
                if d % f == 0:
                    factor_counts[f] += 1

    kasiski_top = factor_counts.most_common(15)
    print(f"\nFactor frequency across all repeated n-gram distances:")
    print(f"{'Factor':>6} {'Count':>6}")
    for f, cnt in kasiski_top:
        print(f"  {f:4d}  {cnt:6d}")
else:
    kasiski_top = []
    print("\nNo repeated n-grams found.")

RESULTS["methods"]["kasiski_examination"] = {
    "ngrams": kasiski_data,
    "all_distances": all_distances,
    "factor_frequency_top15": [{"factor": f, "count": c} for f, c in kasiski_top],
}


# ===================================================================
# 6. PHI TEST
# ===================================================================
print("\n" + "=" * 72)
print("METHOD 6: PHI TEST (Sum of column IC per period)")
print("  phi(p) = sum of IC for each of p columns")
print("  Higher phi => more likely period")
print("=" * 72)

phi_results: list[tuple[int, float]] = []
for p in range(1, 51):
    streams = ['' for _ in range(p)]
    for i, ch in enumerate(K4):
        streams[i % p] += ch

    phi = sum(compute_ic(s) for s in streams)
    phi_results.append((p, phi))

phi_sorted = sorted(phi_results, key=lambda x: -x[1])

print(f"\nTop 15 periods by Phi score:")
print(f"{'Period':>6} {'Phi':>10}")
for p, phi in phi_sorted[:15]:
    print(f"  {p:4d}  {phi:10.6f}")

# Also show all periods 1-50 sorted by period for visual inspection
print(f"\nAll periods 1-50 (by period order):")
print(f"{'Period':>6} {'Phi':>10} {'Avg IC':>10}")
for p, phi in sorted(phi_results):
    avg = phi / p if p > 0 else 0
    marker = " <--" if p in [x[0] for x in phi_sorted[:5]] else ""
    print(f"  {p:4d}  {phi:10.6f}  {avg:10.6f}{marker}")

RESULTS["methods"]["phi_test"] = {
    "top15": [{"period": p, "phi": round(phi, 6)} for p, phi in phi_sorted[:15]],
    "all_periods": [{"period": p, "phi": round(phi, 6)} for p, phi in sorted(phi_results)],
}


# ===================================================================
# CONSENSUS ANALYSIS
# ===================================================================
print("\n" + "=" * 72)
print("CONSENSUS ANALYSIS")
print("  Which periods appear consistently across methods?")
print("=" * 72)

# Gather top-10 periods from each method
method_top10: dict[str, list[int]] = {}

# Method 1: Vigenere autocorrelation - use top lags as potential period factors
method_top10["vigenere_autocorr"] = vig_top_lags[:10]

# Method 2: Beaufort autocorrelation
method_top10["beaufort_autocorr"] = beau_top_lags[:10]

# Method 3: Difference autocorrelation (Vigenere)
method_top10["diff_autocorr_vig"] = [p for p, _, _, _ in vig_diff[:10]]

# Method 3b: Difference autocorrelation (Beaufort)
method_top10["diff_autocorr_beau"] = [p for p, _, _, _ in beau_diff[:10]]

# Method 4: Mutual IC (by column IC)
method_top10["mutual_ic_column"] = [p for p, _, _ in ic_by_ic[:10]]

# Method 4b: Mutual IC (by mutual IC with English)
method_top10["mutual_ic_english"] = [p for p, _, _ in ic_by_mutual[:10]]

# Method 5: Kasiski factors
method_top10["kasiski_factors"] = [f for f, _ in kasiski_top[:10]]

# Method 6: Phi test
method_top10["phi_test"] = [p for p, _ in phi_sorted[:10]]

print("\nTop-10 periods from each method:")
for method, periods in method_top10.items():
    print(f"  {method:25s}: {periods}")

# Count how many methods each period appears in
period_votes: Counter = Counter()
for method, periods in method_top10.items():
    for p in periods:
        period_votes[p] += 1

consensus = period_votes.most_common(20)
print(f"\nConsensus (periods appearing in multiple method top-10s):")
print(f"{'Period':>6} {'Votes':>6} {'Methods'}")
for p, votes in consensus:
    if votes >= 2:
        methods = [m for m, plist in method_top10.items() if p in plist]
        print(f"  {p:4d}  {votes:4d}    {', '.join(methods)}")

# Additional: check which small factors divide the top consensus periods
print(f"\nSmall factor analysis of top consensus periods:")
for p, votes in consensus[:10]:
    factors = [f for f in range(2, p + 1) if p % f == 0] if p > 1 else [1]
    print(f"  period {p}: factors = {factors}, votes = {votes}")

RESULTS["consensus"] = {
    "method_top10": {m: ps for m, ps in method_top10.items()},
    "period_votes": [{"period": p, "votes": v} for p, v in consensus],
    "strong_candidates": [p for p, v in consensus if v >= 3],
}

# ===================================================================
# Additional: Shift pattern analysis
# ===================================================================
print("\n" + "=" * 72)
print("SHIFT PATTERN ANALYSIS")
print("=" * 72)

print("\nVigenere shift sequence at known positions:")
vig_shift_seq = [vig_shifts[p] for p in KNOWN_POSITIONS]
print(f"  Positions: {KNOWN_POSITIONS}")
print(f"  Shifts:    {vig_shift_seq}")
print(f"  Letters:   {''.join(STANDARD_ALPHABET[s] for s in vig_shift_seq)}")

print(f"\nBeaufort shift sequence at known positions:")
beau_shift_seq = [beau_shifts[p] for p in KNOWN_POSITIONS]
print(f"  Positions: {KNOWN_POSITIONS}")
print(f"  Shifts:    {beau_shift_seq}")
print(f"  Letters:   {''.join(STANDARD_ALPHABET[s] for s in beau_shift_seq)}")

# Check if shifts at positions mod p are constant for small p
print(f"\nPeriodicity check: do shifts repeat with period p?")
for p in range(1, 21):
    buckets_vig: dict[int, set[int]] = defaultdict(set)
    buckets_beau: dict[int, set[int]] = defaultdict(set)
    for pos in KNOWN_POSITIONS:
        buckets_vig[pos % p].add(vig_shifts[pos])
        buckets_beau[pos % p].add(beau_shifts[pos])

    # Measure: average number of distinct shifts per bucket (lower = more periodic)
    vig_avg = sum(len(v) for v in buckets_vig.values()) / len(buckets_vig)
    beau_avg = sum(len(v) for v in buckets_beau.values()) / len(buckets_beau)

    vig_consistent = sum(1 for v in buckets_vig.values() if len(v) == 1)
    beau_consistent = sum(1 for v in buckets_beau.values() if len(v) == 1)

    if vig_avg < 2.5 or beau_avg < 2.5:
        print(f"  p={p:2d}: Vig avg_distinct={vig_avg:.2f} ({vig_consistent}/{p} consistent), "
              f"Beau avg_distinct={beau_avg:.2f} ({beau_consistent}/{p} consistent)")

RESULTS["shift_analysis"] = {
    "vigenere_shift_letters": "".join(STANDARD_ALPHABET[s] for s in vig_shift_seq),
    "beaufort_shift_letters": "".join(STANDARD_ALPHABET[s] for s in beau_shift_seq),
}

# ===================================================================
# Save results
# ===================================================================
os.makedirs("runs", exist_ok=True)
output_path = os.path.join("runs", "crib_dragging.json")
with open(output_path, "w") as f:
    json.dump(RESULTS, f, indent=2)

print(f"\n{'=' * 72}")
print(f"Results saved to {output_path}")
print(f"{'=' * 72}")
