"""Strategy 40: Mathematical / Positional Key Generation.

Tests whether K4's key could be derived from a mathematical or positional
process rather than a text source. Explores:

1. COORDINATE-DERIVED KEYS
   K2 plaintext contains coordinates: 38°57'6.5"N, 77°8'44"W
   These numbers could seed the key through various transformations.

2. FIBONACCI / LUCAS SEQUENCES
   Generate key shifts from Fibonacci or Lucas numbers mod 26.

3. MODULAR ARITHMETIC
   Key = f(position) for various functions: linear, quadratic, polynomial,
   exponential mod 26.

4. PRIME SEQUENCES
   Key shifts from prime number sequences.

5. SCULPTURE LAYOUT / POSITIONAL RULES
   Key derived from K4's position on the sculpture, row/column indices
   in grid layouts, or relationships to other panels.

6. COMBINATION RULES
   Key derived from combining K4 ciphertext positions with constants.
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from itertools import product

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

N = len(K4)  # 97

# ---------- known plaintext (0-indexed) ----------
ANCHORS_LIST = [(c, int(d["start_index"]) - 1) for c, d in ANCHOR_COMPONENT_CLUES.items()]
KNOWN_PT = {}
for clue, start in ANCHORS_LIST:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch
KNOWN_POSITIONS = sorted(KNOWN_PT.keys())

# ---------- K2 coordinate data ----------
# "thirtyeightdegreesfiftysevenminutessixpointfivesecondsnorth
#  seventysevendegreeseightminutesfortyfoursecondswest"
# = 38°57'6.5"N, 77°8'44"W
# CIA HQ actual coords: 38.9519°N, 77.1467°W
LAT_DEG = 38
LAT_MIN = 57
LAT_SEC = 6.5
LON_DEG = 77
LON_MIN = 8
LON_SEC = 44

LAT_DECIMAL = LAT_DEG + LAT_MIN / 60 + LAT_SEC / 3600  # 38.9518055...
LON_DECIMAL = LON_DEG + LON_MIN / 60 + LON_SEC / 3600  # 77.1455555...

# All the raw numbers from the coordinates
COORD_NUMBERS = [38, 57, 6, 5, 77, 8, 44]
COORD_DIGITS = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

# ---------- cipher operations ----------
def vigenere_decrypt_shifts(ct, shifts):
    """Decrypt using numeric shift values (0-25)."""
    return "".join(
        chr((ord(c) - 65 - s) % 26 + 65) for c, s in zip(ct, shifts)
    )

def beaufort_decrypt_shifts(ct, shifts):
    return "".join(
        chr((s - (ord(c) - 65)) % 26 + 65) for c, s in zip(ct, shifts)
    )

def quagmire_decrypt_shifts(ct, shifts):
    result = []
    for c, s in zip(ct, shifts):
        ci = KRYPTOS_ALPHABET.index(c) if c in KRYPTOS_ALPHABET else ord(c) - 65
        pi = (ci - s) % 26
        result.append(STANDARD_ALPHABET[pi])
    return "".join(result)

# ---------- scoring ----------
def anchor_score(pt):
    return sum(1 for pos, ch in KNOWN_PT.items() if pos < len(pt) and pt[pos] == ch)

COMMON_BIGRAMS = {
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
    "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
}

def english_score(text):
    bi = sum(1 for i in range(len(text) - 1) if text[i:i+2] in COMMON_BIGRAMS)
    vowels = sum(1 for c in text if c in "AEIOU")
    vr = vowels / len(text) if text else 0
    return bi * 3 + (15 if 0.30 <= vr <= 0.45 else 0)

# ---------- key generation functions ----------

def gen_fibonacci_keys():
    """Generate keys from Fibonacci sequence mod 26."""
    keys = {}
    # Standard Fibonacci
    for a, b in [(0, 1), (1, 1), (1, 2), (2, 1), (1, 3), (3, 1)]:
        seq = []
        x, y = a, b
        for _ in range(N):
            seq.append(x % 26)
            x, y = y, (x + y)
        keys[f"fib({a},{b})"] = seq
    # Fibonacci with different moduli then mod 26
    for mod in [10, 13, 97]:
        seq = []
        x, y = 0, 1
        for _ in range(N):
            seq.append(x % 26)
            x, y = y, (x + y) % mod
        keys[f"fib_mod{mod}"] = seq
    return keys

def gen_lucas_keys():
    """Lucas sequence: L(0)=2, L(1)=1, L(n)=L(n-1)+L(n-2)."""
    keys = {}
    seq = []
    x, y = 2, 1
    for _ in range(N):
        seq.append(x % 26)
        x, y = y, x + y
    keys["lucas"] = seq
    return keys

def gen_coordinate_keys():
    """Generate keys from coordinate data in various ways."""
    keys = {}

    # 1. Raw coordinate digits repeated cyclically
    digits = COORD_DIGITS
    keys["coord_digits_cyclic"] = [digits[i % len(digits)] for i in range(N)]

    # 2. Coordinate numbers repeated cyclically
    nums = COORD_NUMBERS
    keys["coord_nums_cyclic"] = [nums[i % len(nums)] % 26 for i in range(N)]

    # 3. Lat/lon decimal digits
    lat_str = f"{LAT_DECIMAL:.10f}".replace(".", "")
    lon_str = f"{LON_DECIMAL:.10f}".replace(".", "")
    lat_digits = [int(c) for c in lat_str if c.isdigit()]
    lon_digits = [int(c) for c in lon_str if c.isdigit()]

    # Interleaved lat/lon digits
    interleaved = []
    for i in range(max(len(lat_digits), len(lon_digits))):
        if i < len(lat_digits):
            interleaved.append(lat_digits[i])
        if i < len(lon_digits):
            interleaved.append(lon_digits[i])
    keys["coord_decimal_interleaved"] = [interleaved[i % len(interleaved)] for i in range(N)]

    # Lat digits only
    keys["lat_decimal_digits"] = [lat_digits[i % len(lat_digits)] for i in range(N)]
    # Lon digits only
    keys["lon_decimal_digits"] = [lon_digits[i % len(lon_digits)] for i in range(N)]

    # 4. Coordinate-based arithmetic
    # shift[i] = (LAT_DEG * i + LON_DEG) mod 26
    for a, b in [(LAT_DEG, LON_DEG), (LON_DEG, LAT_DEG),
                 (LAT_MIN, LON_MIN), (LON_MIN, LAT_MIN),
                 (LAT_DEG, LAT_MIN), (LON_DEG, LON_MIN)]:
        keys[f"linear({a},{b})"] = [(a * i + b) % 26 for i in range(N)]

    # 5. Digits of lat * lon
    product_val = LAT_DECIMAL * LON_DECIMAL
    prod_str = f"{product_val:.15f}".replace(".", "")
    prod_digits = [int(c) for c in prod_str if c.isdigit()]
    keys["lat_x_lon_digits"] = [prod_digits[i % len(prod_digits)] for i in range(N)]

    # 6. Sum of coordinate pairs mod 26
    keys["coord_pair_sums"] = [(COORD_NUMBERS[i % len(COORD_NUMBERS)] +
                                 COORD_NUMBERS[(i + 1) % len(COORD_NUMBERS)]) % 26
                                for i in range(N)]

    # 7. Running sum of coordinate digits
    running = []
    s = 0
    for i in range(N):
        s = (s + COORD_DIGITS[i % len(COORD_DIGITS)]) % 26
        running.append(s)
    keys["coord_digits_running_sum"] = running

    # 8. Coordinate digits as key letters (A=0, ..., Z=25)
    keys["coord_digits_shifted"] = [(d + 9) % 26 for d in
                                     [COORD_DIGITS[i % len(COORD_DIGITS)] for i in range(N)]]

    return keys

def gen_modular_arithmetic_keys():
    """Generate keys from various modular arithmetic functions."""
    keys = {}

    # Linear: shift = (a*i + b) mod 26
    for a in range(1, 26):
        for b in range(26):
            keys[f"lin_{a}_{b}"] = [(a * i + b) % 26 for i in range(N)]

    # Quadratic: shift = (a*i^2 + b*i + c) mod 26
    for a in [1, 2, 3, 5, 7, 11, 13]:
        for b in [0, 1, 3, 7, 13]:
            for c in [0, 1, 5, 11, 19]:
                keys[f"quad_{a}_{b}_{c}"] = [(a * i * i + b * i + c) % 26 for i in range(N)]

    # Exponential: shift = (base^i) mod 26
    for base in range(2, 26):
        if math.gcd(base, 26) == 1:  # only coprime bases
            keys[f"exp_{base}"] = [pow(base, i, 26) for i in range(N)]

    return keys

def gen_prime_keys():
    """Generate keys from prime number sequences."""
    keys = {}

    # First 97 primes mod 26
    primes = []
    n = 2
    while len(primes) < N:
        if all(n % p != 0 for p in primes if p * p <= n):
            primes.append(n)
        n += 1
    keys["primes_mod26"] = [p % 26 for p in primes]

    # Cumulative sum of primes mod 26
    running = []
    s = 0
    for p in primes:
        s = (s + p) % 26
        running.append(s)
    keys["primes_running_sum"] = running

    # Prime gaps mod 26
    gaps = [primes[i + 1] - primes[i] for i in range(N - 1)]
    gaps.append(gaps[-1])  # pad
    keys["prime_gaps_mod26"] = [g % 26 for g in gaps]

    # Primes shifted by coordinate values
    keys["primes_plus_lat"] = [(primes[i] + LAT_DEG) % 26 for i in range(N)]
    keys["primes_plus_lon"] = [(primes[i] + LON_DEG) % 26 for i in range(N)]

    return keys

def gen_positional_keys():
    """Generate keys from K4's position on the sculpture and grid layouts."""
    keys = {}

    # Grid-based: 7x14 layout
    for nrows, ncols in [(7, 14), (14, 7), (8, 13), (13, 8), (11, 9), (9, 11), (97, 1), (1, 97)]:
        # Row index as shift
        keys[f"grid_{nrows}x{ncols}_row"] = [(i // ncols) % 26 for i in range(N)]
        # Column index as shift
        keys[f"grid_{nrows}x{ncols}_col"] = [(i % ncols) % 26 for i in range(N)]
        # Row + column
        keys[f"grid_{nrows}x{ncols}_rowcol"] = [((i // ncols) + (i % ncols)) % 26 for i in range(N)]
        # Row * column
        keys[f"grid_{nrows}x{ncols}_rowXcol"] = [((i // ncols) * (i % ncols)) % 26 for i in range(N)]
        # Diagonal index
        keys[f"grid_{nrows}x{ncols}_diag"] = [((i // ncols) + (i % ncols)) % 26 for i in range(N)]

    # Position in KRYPTOS alphabet
    krypt_idx = []
    for c in K4:
        if c in KRYPTOS_ALPHABET:
            krypt_idx.append(KRYPTOS_ALPHABET.index(c))
        else:
            krypt_idx.append(ord(c) - 65)
    keys["k4_kryptos_index"] = krypt_idx

    # XOR of position with ciphertext
    keys["pos_xor_ct"] = [(i ^ (ord(K4[i]) - 65)) % 26 for i in range(N)]

    # Position + ciphertext value mod 26
    keys["pos_plus_ct"] = [(i + ord(K4[i]) - 65) % 26 for i in range(N)]

    # Position * ciphertext value mod 26
    keys["pos_times_ct"] = [(i * (ord(K4[i]) - 65)) % 26 for i in range(N)]

    # Ciphertext value of previous character
    keys["ct_shifted_1"] = [0] + [ord(K4[i]) - 65 for i in range(N - 1)]
    keys["ct_shifted_2"] = [0, 0] + [ord(K4[i]) - 65 for i in range(N - 2)]

    # Sum of all previous ciphertext values mod 26
    running_ct = []
    s = 0
    for i in range(N):
        running_ct.append(s % 26)
        s += ord(K4[i]) - 65
    keys["ct_running_sum"] = running_ct

    # K1/K2/K3 plaintext values at same position (cycled)
    for name, pt in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
        keys[f"{name}_position_match"] = [ord(pt[i % len(pt)]) - 65 for i in range(N)]

    return keys

def gen_kryptos_word_keys():
    """Generate keys from Kryptos-related words and phrases."""
    keys = {}

    words = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "EASTNORTHEAST", "BERLINCLOCK", "LATITUDE", "LONGITUDE",
        "SANBORN", "SCHEIDT", "CIA", "LANGLEY", "VIRGINIA",
        "SHADOW", "ILLUSION", "LUCENT", "IQLUSION",
        "TUTANKHAMUN", "CARTER", "HOWARD", "PHARAOH",
        "NORTHEAST", "NORTHWEST", "SOUTHEAST", "SOUTHWEST",
        "KRYPTOSABCDEFGHIJLMNQUVWXZ",  # the full KRYPTOS alphabet
    ]

    for word in words:
        shifts = [ord(c) - 65 for c in word]
        # Simple repeating keyword
        keys[f"word_{word}"] = [shifts[i % len(shifts)] for i in range(N)]
        # Keyword with progressive offset
        for offset in [1, 2, 3, 5, 7]:
            keys[f"word_{word}_prog{offset}"] = [
                (shifts[i % len(shifts)] + i * offset) % 26 for i in range(N)
            ]

    return keys

def gen_combined_keys():
    """Generate keys that combine coordinate data with other sequences."""
    keys = {}

    # Fibonacci seeded with coordinate values
    for seed_a, seed_b, label in [
        (LAT_DEG, LON_DEG, "latlon"),
        (LAT_MIN, LON_MIN, "latmin_lonmin"),
        (LAT_SEC, LON_SEC, "latsec_lonsec"),
    ]:
        seq = []
        x, y = int(seed_a), int(seed_b)
        for _ in range(N):
            seq.append(x % 26)
            x, y = y, (x + y) % 26
        keys[f"fib_coord_{label}"] = seq

    # KRYPTOS alphabet index + position mod 26
    for offset in range(26):
        k = []
        for i in range(N):
            ci = KRYPTOS_ALPHABET.index(K4[i]) if K4[i] in KRYPTOS_ALPHABET else ord(K4[i]) - 65
            k.append((ci + i + offset) % 26)
        keys[f"kryptos_idx_pos_off{offset}"] = k

    # Coordinate digits Fibonacci: use coord digits as initial Fibonacci seeds
    for start in range(len(COORD_DIGITS) - 1):
        a, b = COORD_DIGITS[start], COORD_DIGITS[start + 1]
        seq = []
        x, y = a, b
        for _ in range(N):
            seq.append(x % 26)
            x, y = y, (x + y) % 26
        keys[f"coord_fib_start{start}"] = seq

    return keys

def gen_constrained_keys():
    """Work backwards from known plaintext to derive what the key MUST be
    at known positions, then test if those values fit any pattern."""
    print("\n--- Constraint Analysis: What key values are forced? ---")

    # For Vigenere: key[i] = (C[i] - P[i]) mod 26
    vig_key = {}
    for pos, pch in KNOWN_PT.items():
        vig_key[pos] = (ord(K4[pos]) - ord(pch)) % 26

    print("\n  Vigenere forced key values:")
    print("  Pos | CT | PT | Key | Letter")
    for pos in KNOWN_POSITIONS:
        ct = K4[pos]
        pt = KNOWN_PT[pos]
        kv = vig_key[pos]
        kl = chr(kv + 65)
        print(f"  {pos:3d} | {ct}  | {pt}  |  {kv:2d} | {kl}")

    # Extract the key sequence at known positions
    known_key_vals = [vig_key[pos] for pos in KNOWN_POSITIONS]
    known_key_letters = "".join(chr(v + 65) for v in known_key_vals)
    print(f"\n  Key at known positions: {known_key_letters}")
    print(f"  Key values: {known_key_vals}")

    # Check if these fit any pattern
    # 1. Constant?
    if len(set(known_key_vals)) == 1:
        print("  -> CONSTANT KEY (Caesar cipher)")

    # 2. Periodic?
    for period in range(1, 25):
        consistent = True
        for i, pos in enumerate(KNOWN_POSITIONS):
            for j, pos2 in enumerate(KNOWN_POSITIONS):
                if pos % period == pos2 % period and known_key_vals[i] != known_key_vals[j]:
                    consistent = False
                    break
            if not consistent:
                break
        if consistent:
            print(f"  -> PERIODIC with period {period}")

    # 3. Linear (key = a*pos + b)?
    # Check all pairs and see if they define the same line
    linear_solutions = []
    for i in range(len(KNOWN_POSITIONS)):
        for j in range(i + 1, len(KNOWN_POSITIONS)):
            p1, k1 = KNOWN_POSITIONS[i], known_key_vals[i]
            p2, k2 = KNOWN_POSITIONS[j], known_key_vals[j]
            dp = (p2 - p1) % 26
            dk = (k2 - k1) % 26
            # a * dp = dk mod 26
            # Try all a
            for a in range(26):
                if (a * dp) % 26 == dk:
                    b = (k1 - a * p1) % 26
                    # Verify against ALL known positions
                    if all((a * KNOWN_POSITIONS[x] + b) % 26 == known_key_vals[x]
                           for x in range(len(KNOWN_POSITIONS))):
                        linear_solutions.append((a, b))
    linear_solutions = list(set(linear_solutions))
    if linear_solutions:
        print(f"  -> LINEAR SOLUTIONS: {linear_solutions[:10]}")
        for a, b in linear_solutions[:5]:
            full_key = [(a * i + b) % 26 for i in range(N)]
            key_str = "".join(chr(v + 65) for v in full_key)
            print(f"     key({a},{b}) = {key_str[:40]}...")

    # 4. Differences between consecutive known key values
    diffs = [(known_key_vals[i + 1] - known_key_vals[i]) % 26
             for i in range(len(known_key_vals) - 1)]
    print(f"\n  Key value differences: {diffs}")

    # 5. Check if key values match any word at those positions
    for name, source in [("KRYPTOS_ALPHA", KRYPTOS_ALPHABET),
                          ("K1_PT", K1_PT), ("K2_PT", K2_PT), ("K3_PT", K3_PT)]:
        if len(source) >= max(KNOWN_POSITIONS) + 1:
            matches = sum(1 for pos, kv in zip(KNOWN_POSITIONS, known_key_vals)
                         if ord(source[pos]) - 65 == kv)
            if matches >= 3:
                print(f"  Source '{name}' matches {matches}/{len(KNOWN_POSITIONS)} key positions")

    # 6. Fibonacci check: do the diffs follow Fibonacci?
    fib = [0, 1]
    while len(fib) < 30:
        fib.append((fib[-1] + fib[-2]) % 26)
    # Check if diffs are a subsequence of Fibonacci mod 26
    for start in range(len(fib) - len(diffs)):
        if fib[start:start + len(diffs)] == diffs:
            print(f"  -> Key diffs match Fibonacci starting at index {start}!")

    # Return forced key for use in full-key generation
    return vig_key, known_key_vals

def gen_interpolated_keys(vig_key):
    """Given forced key values at known positions, try to interpolate
    the full key using various mathematical functions."""
    keys = {}

    positions = KNOWN_POSITIONS
    values = [vig_key[p] for p in positions]

    # Linear interpolation (just use the two clusters)
    # Cluster 1: positions 21-33 (EASTNORTHEAST)
    # Cluster 2: positions 63-73 (BERLINCLOCK)
    cluster1_pos = [p for p in positions if p <= 33]
    cluster1_val = [vig_key[p] for p in cluster1_pos]
    cluster2_pos = [p for p in positions if p >= 63]
    cluster2_val = [vig_key[p] for p in cluster2_pos]

    # Average key value per cluster
    avg1 = sum(cluster1_val) / len(cluster1_val)
    avg2 = sum(cluster2_val) / len(cluster2_val)
    avg_pos1 = sum(cluster1_pos) / len(cluster1_pos)
    avg_pos2 = sum(cluster2_pos) / len(cluster2_pos)

    # Linear fit between clusters
    if avg_pos2 != avg_pos1:
        slope = (avg2 - avg1) / (avg_pos2 - avg_pos1)
        intercept = avg1 - slope * avg_pos1
        keys["linear_interp"] = [int(round(slope * i + intercept)) % 26 for i in range(N)]

    # Nearest-known-value fill
    nearest_key = [0] * N
    for i in range(N):
        closest = min(positions, key=lambda p: abs(p - i))
        nearest_key[i] = vig_key[closest]
    keys["nearest_fill"] = nearest_key

    # Constant-within-cluster, average between
    for fill_val in range(26):
        k = [fill_val] * N
        for p, v in vig_key.items():
            k[p] = v
        keys[f"forced_fill_{fill_val}"] = k

    return keys


# ========== MAIN ==========
def main():
    print("=" * 70)
    print("Strategy 40: Mathematical / Positional Key Generation")
    print("=" * 70)
    print(f"K4: {K4}")
    print(f"Known positions: {len(KNOWN_PT)} chars")
    print()

    decrypt_fns = {
        "Vig": vigenere_decrypt_shifts,
        "Beau": beaufort_decrypt_shifts,
        "Quag": quagmire_decrypt_shifts,
    }

    all_candidates = []
    total_attempts = 0
    start_time = time.time()

    # --- Constraint analysis first ---
    vig_key, known_key_vals = gen_constrained_keys()

    # --- Generate all key families ---
    key_families = {}
    families = [
        ("Fibonacci", gen_fibonacci_keys),
        ("Lucas", gen_lucas_keys),
        ("Coordinates", gen_coordinate_keys),
        ("Primes", gen_prime_keys),
        ("Positional", gen_positional_keys),
        ("Kryptos_Words", gen_kryptos_word_keys),
        ("Combined", gen_combined_keys),
        ("Interpolated", lambda: gen_interpolated_keys(vig_key)),
    ]

    # Modular arithmetic is large, add separately
    families.append(("Modular", gen_modular_arithmetic_keys))

    for family_name, gen_fn in families:
        fam_keys = gen_fn()
        key_families[family_name] = fam_keys
        print(f"\n  {family_name}: {len(fam_keys)} keys generated")

    total_keys = sum(len(v) for v in key_families.values())
    print(f"\nTotal keys to test: {total_keys}")
    print(f"Total attempts: {total_keys * len(decrypt_fns)}")

    # --- Test all keys ---
    print("\n--- Testing all keys ---")
    for family_name, fam_keys in key_families.items():
        family_best = {"hits": 0}
        family_start = time.time()

        for key_name, shifts in fam_keys.items():
            for model_name, decrypt_fn in decrypt_fns.items():
                pt = decrypt_fn(K4, shifts)
                total_attempts += 1

                a = anchor_score(pt)
                if a > family_best["hits"]:
                    family_best = {
                        "hits": a,
                        "key": key_name,
                        "model": model_name,
                        "pt_preview": pt[:50],
                    }
                if a >= 8:
                    e = english_score(pt)
                    all_candidates.append({
                        "score": a * 40 + e,
                        "anchor_hits": a,
                        "english_score": e,
                        "family": family_name,
                        "key_name": key_name,
                        "model": model_name,
                        "plaintext": pt,
                        "shifts_preview": shifts[:20],
                    })

        fam_elapsed = time.time() - family_start
        fb = family_best
        print(f"  {family_name:20s}: best {fb['hits']:2d}/24 "
              f"({fb.get('model','?')} / {fb.get('key','?')[:40]}) [{fam_elapsed:.2f}s]")

    elapsed = time.time() - start_time
    all_candidates.sort(key=lambda x: x["score"], reverse=True)

    print(f"\n{'=' * 70}")
    print(f"TOTAL: {total_attempts:,} attempts in {elapsed:.1f}s")
    print(f"Candidates with >= 8 anchor hits: {len(all_candidates)}")
    print(f"{'=' * 70}")

    if all_candidates:
        print(f"\nTop 15 candidates:")
        for i, c in enumerate(all_candidates[:15]):
            print(f"\n  #{i+1} | Anchors: {c['anchor_hits']}/24 | Score: {c['score']}")
            print(f"       Family: {c['family']} | Key: {c['key_name']} | Model: {c['model']}")
            print(f"       PT: {c['plaintext'][:80]}")
            print(f"       Shifts: {c['shifts_preview']}")
    else:
        print("\nNo candidates reached >= 8 anchor hits.")
        print("Mathematical key generation does not produce anchor-consistent")
        print("decryptions under standard polyalphabetic models.")

    # Special analysis: forced-fill keys (these guarantee anchor matches by construction)
    print("\n--- Forced-fill analysis (guaranteed anchor matches) ---")
    for fill in range(26):
        key_name = f"forced_fill_{fill}"
        shifts = key_families["Interpolated"][key_name]
        for model_name, decrypt_fn in decrypt_fns.items():
            pt = decrypt_fn(K4, shifts)
            a = anchor_score(pt)
            e = english_score(pt)
            if e > 30 or a >= 20:  # English-like outside anchors
                fill_letter = chr(fill + 65)
                print(f"  Fill={fill_letter}: {model_name} anchors={a}/24 english={e}")
                print(f"    PT: {pt}")

    # Save
    output = {
        "strategy_id": "40",
        "name": "Mathematical / Positional Key Generation",
        "total_attempts": total_attempts,
        "elapsed_seconds": round(elapsed, 1),
        "key_families": {k: len(v) for k, v in key_families.items()},
        "candidate_count": len(all_candidates),
        "forced_key_analysis": {
            "known_positions": KNOWN_POSITIONS,
            "vigenere_key_values": [vig_key[p] for p in KNOWN_POSITIONS],
            "vigenere_key_letters": "".join(chr(vig_key[p] + 65) for p in KNOWN_POSITIONS),
        },
        "top_candidates": all_candidates[:50],
    }
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "runs", "mathematical_key_generation.json",
    )
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
