"""Exhaustive search over unconstrained Vigenere key slots.

For each top (transposition, Vigenere period) config from constraint_first_sweep:
- The constrained key slots are fixed by known plaintext
- Brute-force ALL 26^N combinations for the N unconstrained slots
- Score each with n-gram language model
- Report the best

Priority: p=28 configs (4 unconstrained = 456K combos each, ~2s per config)
Then:     p=29 configs (5 unconstrained = 12M combos — use pruning)
"""
from __future__ import annotations

import sys
import time
import json
import math

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, ANCHOR_COMPONENT_CLUES, KNOWN_PLAINTEXT_CLUES, STANDARD_ALPHABET,
)
from kryptos.common import (
    build_score_breakdown, anchor_alignment_score, language_shape_score,
    decrypt_vigenere_standard, iter_anchor_components, iter_known_plaintext_segments,
)
from kryptos.transposition import (
    periodic_transposition_decrypt, keyword_permutation,
)

N = len(K4)

# Known plaintext (0-indexed)
KNOWN_PT: dict[int, str] = {}
for _c, _d in ANCHOR_COMPONENT_CLUES.items():
    s = int(_d["start_index"]) - 1
    for i, ch in enumerate(_c):
        KNOWN_PT[s + i] = ch

# Precompute bigram log-prob table (26x26)
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

# Build fast int lookup tables
BG_TABLE = [[OTHER_BG] * 26 for _ in range(26)]
for bg, lp in BIGRAM_LOG.items():
    BG_TABLE[ord(bg[0])-65][ord(bg[1])-65] = lp

TG_TABLE = [[[OTHER_TG] * 26 for _ in range(26)] for _ in range(26)]
for tg, lp in TRIGRAM_LOG.items():
    TG_TABLE[ord(tg[0])-65][ord(tg[1])-65][ord(tg[2])-65] = lp


def fast_ngram_score(pt_ints: list[int]) -> float:
    """Score using precomputed int lookup tables."""
    s = 0.0
    n = len(pt_ints)
    for i in range(n - 1):
        s += BG_TABLE[pt_ints[i]][pt_ints[i+1]]
    for i in range(n - 2):
        s += TG_TABLE[pt_ints[i]][pt_ints[i+1]][pt_ints[i+2]] * 1.5
    return s


def derive_constrained_shifts(intermediate: str, period: int) -> tuple[list[int], list[int]]:
    """Derive Vigenere key shifts from known plaintext.
    Returns (shifts, unconstrained_slots) where shifts[i]=-1 for unconstrained.
    """
    shifts = [-1] * period
    for pos, plain_char in KNOWN_PT.items():
        if pos >= len(intermediate):
            continue
        ci = ord(intermediate[pos]) - 65
        pi = ord(plain_char) - 65
        required = (ci - pi) % 26
        slot = pos % period
        if shifts[slot] >= 0 and shifts[slot] != required:
            return None, None  # Inconsistent
        shifts[slot] = required
    unconstrained = [i for i in range(period) if shifts[i] < 0]
    return shifts, unconstrained


def exhaustive_search(intermediate: str, period: int,
                      base_shifts: list[int], unconstrained: list[int]) -> dict:
    """Brute-force all combinations of unconstrained key slots."""
    n = len(intermediate)
    inter_ints = [ord(c) - 65 for c in intermediate]

    # Precompute: for each position, which key slot does it use?
    pos_to_slot = [i % period for i in range(n)]

    # Precompute: which positions are affected by each unconstrained slot?
    slot_positions: dict[int, list[int]] = {}
    for slot in unconstrained:
        slot_positions[slot] = [i for i in range(n) if pos_to_slot[i] == slot]

    # Build baseline plaintext ints (unconstrained slots get shift=0 initially)
    shifts = list(base_shifts)
    for slot in unconstrained:
        shifts[slot] = 0

    pt_ints = [(inter_ints[i] - shifts[pos_to_slot[i]]) % 26 for i in range(n)]

    best_score = fast_ngram_score(pt_ints)
    best_shifts = list(shifts)
    best_pt = list(pt_ints)

    num_unc = len(unconstrained)
    total = 26 ** num_unc
    checked = 0

    if num_unc == 0:
        pass
    elif num_unc <= 4:
        # Full exhaustive: up to 456,976 combos
        for combo in range(total):
            # Decode combo into shift values
            val = combo
            new_shifts_vals = []
            for _ in range(num_unc):
                new_shifts_vals.append(val % 26)
                val //= 26

            # Update affected positions in pt_ints
            for idx, slot in enumerate(unconstrained):
                new_s = new_shifts_vals[idx]
                if new_s != shifts[slot]:
                    old_s = shifts[slot]
                    shifts[slot] = new_s
                    for pos in slot_positions[slot]:
                        pt_ints[pos] = (inter_ints[pos] - new_s) % 26

            score = fast_ngram_score(pt_ints)
            checked += 1

            if score > best_score:
                best_score = score
                best_shifts = list(shifts)
                best_pt = list(pt_ints)

    elif num_unc == 5:
        # 5 unconstrained: 12M combos. Do staged search.
        # Stage 1: Fix slots 0-2, sweep slots 3-4 (26^2=676 per outer combo)
        # Stage 2: For top outer combos, fine-tune all 5
        # This reduces from 12M to ~26^3 * 676 ≈ 12M but with early pruning

        # Actually just do it — 12M is ~10-20s with fast scoring
        for s0 in range(26):
            shifts[unconstrained[0]] = s0
            for pos in slot_positions[unconstrained[0]]:
                pt_ints[pos] = (inter_ints[pos] - s0) % 26

            for s1 in range(26):
                shifts[unconstrained[1]] = s1
                for pos in slot_positions[unconstrained[1]]:
                    pt_ints[pos] = (inter_ints[pos] - s1) % 26

                for s2 in range(26):
                    shifts[unconstrained[2]] = s2
                    for pos in slot_positions[unconstrained[2]]:
                        pt_ints[pos] = (inter_ints[pos] - s2) % 26

                    for s3 in range(26):
                        shifts[unconstrained[3]] = s3
                        for pos in slot_positions[unconstrained[3]]:
                            pt_ints[pos] = (inter_ints[pos] - s3) % 26

                        for s4 in range(26):
                            shifts[unconstrained[4]] = s4
                            for pos in slot_positions[unconstrained[4]]:
                                pt_ints[pos] = (inter_ints[pos] - s4) % 26

                            score = fast_ngram_score(pt_ints)
                            checked += 1

                            if score > best_score:
                                best_score = score
                                best_shifts = list(shifts)
                                best_pt = list(pt_ints)

    text = "".join(STANDARD_ALPHABET[p] for p in best_pt)
    key = "".join(STANDARD_ALPHABET[s] if s >= 0 else "?" for s in best_shifts)

    return {
        "text": text,
        "key": key,
        "shifts": best_shifts,
        "ngram_score": best_score,
        "checked": checked,
    }


def analyze_key(key: str, period: int) -> dict:
    """Analyze a key for keyword structure."""
    # Check against keyword_permutation for all common words
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN",
        "SHADOW", "ILLUSION", "EAST", "NORTHEAST", "EGYPT", "CARTER",
        "LANGLEY", "TOMB", "LUCENT", "MESSAGE", "DELIVER", "WORLD",
        "ALEXANDERPLATZ", "ZEITUHR", "POSITION", "INVISIBLE", "BETWEEN",
        "SUBTLE", "SHADING", "ABSENCE", "LIGHT", "NUANCE", "IQLUSION",
        "SLOWLY", "DESPERATELY", "REMAINS", "PASSAGE", "DEBRIS",
        "MAGNETIC", "FIELD", "UNDERGROUND", "LOCATION", "BURIED",
    ]
    # Look for the key as a substring of any keyword repeated
    matches = []
    for kw in keywords:
        extended = (kw * ((period // len(kw)) + 2))[:period * 2]
        for offset in range(len(kw)):
            candidate = extended[offset:offset + period]
            if len(candidate) >= period:
                # Compare: how many positions match?
                hits = sum(1 for a, b in zip(key, candidate) if a == b)
                if hits >= period * 0.6:
                    matches.append((kw, offset, hits, candidate[:period]))
    matches.sort(key=lambda x: -x[2])
    return {"keyword_matches": matches[:5]}


def check_perm_keyword_origin(perm: list[int]) -> list[str]:
    """Check if a permutation could derive from keyword_permutation."""
    width = len(perm)
    perm_tuple = tuple(perm)
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN",
        "SHADOW", "ILLUSION", "EAST", "NORTHEAST", "EGYPT", "CARTER",
        "LANGLEY", "TOMB", "LUCENT", "MESSAGE", "DELIVER", "WORLD",
        "ALEXANDERPLATZ", "ZEITUHR", "POSITION", "INVISIBLE",
    ]
    matches = []
    for kw in keywords:
        derived = keyword_permutation(kw, width)
        if derived == perm_tuple:
            matches.append(kw)
    return matches


def main():
    t0 = time.perf_counter()

    # Load configs from constraint_first_sweep
    with open("runs/constraint_first_deep.json") as f:
        data = json.load(f)

    # Deduplicate configs by (period, width, perm, fill, read)
    configs = []
    seen = set()
    for r in data["top_results"]:
        sig = (r["vig_period"], r["width"], tuple(r["permutation"]),
               r["fill_mode"], r["read_mode"])
        if sig not in seen:
            seen.add(sig)
            configs.append(r)

    # Sort: p=28 first (4 unconstrained), then p=29 (5 unconstrained)
    configs.sort(key=lambda x: (x["vig_period"] - x["constrained_slots"],
                                -x["project_score"]))

    print("=" * 78)
    print("EXHAUSTIVE KEY SEARCH")
    print("=" * 78)

    all_results = []

    for idx, cfg in enumerate(configs):
        period = cfg["vig_period"]
        width = cfg["width"]
        perm = cfg["permutation"]
        fill = cfg["fill_mode"]
        read = cfg["read_mode"]

        inter = periodic_transposition_decrypt(K4, width, tuple(perm),
                                               fill_mode=fill, read_mode=read)
        base_shifts, unconstrained = derive_constrained_shifts(inter, period)
        if base_shifts is None:
            continue

        num_unc = len(unconstrained)
        total_combos = 26 ** num_unc

        t1 = time.perf_counter()
        result = exhaustive_search(inter, period, base_shifts, unconstrained)
        dt = time.perf_counter() - t1

        text = result["text"]
        bd = build_score_breakdown(text)
        fs = anchor_alignment_score(text) + language_shape_score(text)

        result.update({
            "vig_period": period, "width": width, "permutation": perm,
            "fill_mode": fill, "read_mode": read,
            "project_score": bd["total"], "anchor": bd["anchor"],
            "language": bd["language"], "domain": bd["domain"],
            "full_score": fs, "unconstrained_count": num_unc,
        })
        all_results.append(result)

        marker = " <<<" if bd["total"] >= 780 else ""
        print(f"[{idx+1:>2}/{len(configs)}] p={period:>2} w={width} "
              f"perm={str(perm):>22} unc={num_unc} "
              f"checked={result['checked']:>12,} in {dt:>5.1f}s  "
              f"proj={bd['total']:>3}/1000 lang={bd['language']:>3} "
              f"key={result['key']}{marker}")

    # Sort by project score
    all_results.sort(key=lambda x: x["project_score"], reverse=True)

    elapsed = time.perf_counter() - t0
    print(f"\n{'=' * 78}")
    print(f"RESULTS ({elapsed:.1f}s total)")
    print(f"{'=' * 78}\n")

    for i, r in enumerate(all_results[:15]):
        text = r["text"]
        print(f"#{i+1:>2} proj={r['project_score']:>3}/1000 "
              f"anch={r['anchor']:>4} lang={r['language']:>3} dom={r['domain']:>3} "
              f"p={r['vig_period']:>2} w={r['width']} "
              f"key={r['key']}")
        print(f"     {text}")

        # Check anchors
        for clue, start, seg in iter_anchor_components(text):
            status = "OK" if seg == clue else f"MISS ({seg})"
            if seg != clue:
                print(f"     WARNING: {clue} at {start}: {status}")

        # English words
        words_3 = ["THE","AND","FOR","ARE","BUT","NOT","YOU","ALL","CAN","HER",
                    "WAS","ONE","OUR","OUT","HIS","HAS","ITS"]
        words_4 = ["THAT","THIS","WITH","HAVE","FROM","THEY","BEEN","SAID","EACH",
                    "WHICH","TIME","WILL","OVER","TION","MENT","THER","HERE","IGHT",
                    "INTO","SOME","WHEN","VERY","NESS","ABLE"]
        words_5 = ["THERE","WHERE","THEIR","ABOUT","WOULD","OTHER","WHICH","AFTER",
                    "COULD","THESE","ATION","UTION","LIGHT","WORLD","CLOCK"]
        found = []
        for w in words_5 + words_4 + words_3:
            idx2 = text.find(w)
            while idx2 >= 0:
                # Skip anchors
                if not (21 <= idx2 <= 33 or 63 <= idx2 <= 73):
                    found.append((w, idx2))
                idx2 = text.find(w, idx2 + 1)
        if found:
            found.sort(key=lambda x: -len(x[0]))
            print(f"     English: {found[:10]}")
        print()

    # Key analysis
    print(f"\n{'=' * 78}")
    print("KEY AND PERMUTATION ANALYSIS")
    print(f"{'=' * 78}\n")

    for i, r in enumerate(all_results[:10]):
        key = r["key"]
        period = r["vig_period"]
        perm = r["permutation"]
        print(f"--- #{i+1} (proj={r['project_score']}) ---")
        print(f"Key ({period}): {key}")
        print(f"Shifts: {r['shifts']}")

        # Key analysis
        ka = analyze_key(key, period)
        if ka["keyword_matches"]:
            for kw, off, hits, cand in ka["keyword_matches"]:
                print(f"  Key ~ {kw} (offset={off}, {hits}/{period} chars match)")

        # Permutation analysis
        perm_kws = check_perm_keyword_origin(perm)
        if perm_kws:
            print(f"  Perm {perm} derives from keyword: {perm_kws}")
        else:
            print(f"  Perm {perm}: no keyword match found")
        print()

    # Save
    output = {
        "type": "exhaustive_key_search",
        "elapsed": elapsed,
        "results": [
            {k: v for k, v in r.items() if k != "shifts"}
            for r in all_results[:25]
        ],
    }
    with open("runs/exhaustive_key_search.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"Saved to runs/exhaustive_key_search.json")


if __name__ == "__main__":
    main()
