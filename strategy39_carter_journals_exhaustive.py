"""Strategy 39: Exhaustive Carter Journals Running-Key Attack.

Tests every 97-character alpha window from ALL THREE seasons of Howard Carter's
Tutankhamun excavation journals (Griffith Institute transcripts) as running keys
against K4 under Vigenere, Beaufort, and Quagmire III cipher models.

Sources:
  Season 1: Oct 28 - Dec 31, 1922  (~29KB)
  Season 2: Oct 3, 1923 - Feb 11, 1924  (~56KB)
  Season 3: Jan 19 - Mar 31, 1925  (~15KB)

Total: ~100KB raw text, ~75K alpha characters = ~75K windows per cipher model.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kryptos.constants import (
    K4,
    KRYPTOS_ALPHABET,
    STANDARD_ALPHABET,
    ANCHOR_COMPONENT_CLUES,
)

# ---------- known plaintext (0-indexed) ----------
ANCHORS_LIST = [(c, int(d["start_index"]) - 1) for c, d in ANCHOR_COMPONENT_CLUES.items()]
KNOWN_PT = {}
for clue, start in ANCHORS_LIST:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

KNOWN_POSITIONS = sorted(KNOWN_PT.keys())
N = len(K4)  # 97

# ---------- cipher operations ----------
def vigenere_decrypt(ct, key):
    return "".join(chr((ord(c) - ord(k)) % 26 + 65) for c, k in zip(ct, key))

def beaufort_decrypt(ct, key):
    return "".join(chr((ord(k) - ord(c)) % 26 + 65) for c, k in zip(ct, key))

def quagmire_decrypt(ct, key):
    result = []
    for c, k in zip(ct, key):
        ci = KRYPTOS_ALPHABET.index(c) if c in KRYPTOS_ALPHABET else ord(c) - 65
        ki = KRYPTOS_ALPHABET.index(k) if k in KRYPTOS_ALPHABET else ord(k) - 65
        pi = (ci - ki) % 26
        result.append(STANDARD_ALPHABET[pi])
    return "".join(result)

# ---------- scoring ----------
def anchor_score(pt):
    return sum(1 for pos, ch in KNOWN_PT.items() if pos < len(pt) and pt[pos] == ch)

COMMON_BIGRAMS = {
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
    "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
    "VE", "CO", "ME", "DE", "HI", "RI", "RO", "IC", "NE", "EA",
}

def english_bigram_score(text):
    return sum(1 for i in range(len(text) - 1) if text[i:i+2] in COMMON_BIGRAMS)

def vowel_ratio(text):
    return sum(1 for c in text if c in "AEIOU") / len(text) if text else 0

# ---------- transposition ----------
def columnar_decrypt(ct, ncols, perm):
    n = len(ct)
    nrows = (n + ncols - 1) // ncols
    full_cols = n % ncols or ncols
    col_lengths = [nrows if i < full_cols else nrows - 1 for i in range(ncols)]
    cols = [""] * ncols
    pos = 0
    for col_idx in perm:
        clen = col_lengths[col_idx]
        cols[col_idx] = ct[pos:pos + clen]
        pos += clen
    result = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return "".join(result)

def keyword_permutation(keyword):
    indexed = sorted(range(len(keyword)), key=lambda i: keyword[i])
    perm = [0] * len(keyword)
    for rank, idx in enumerate(indexed):
        perm[idx] = rank
    return sorted(range(len(keyword)), key=lambda i: perm[i])

# ---------- load all journals ----------
def load_journal(filename):
    path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "kryptos", "data", "corpora", filename,
    )
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    return re.sub(r"[^A-Za-z]", "", raw).upper()

def main():
    print("=" * 70)
    print("Strategy 39: Exhaustive Carter Journals Running-Key Attack")
    print("=" * 70)

    # Load all sources
    sources = {
        "Season1_1922": load_journal("carter_journal_season1.txt"),
        "Season2_1923": load_journal("carter_journal_season2.txt"),
        "Season3_1925": load_journal("carter_journal_season3.txt"),
        "Nov26_Diary": load_journal("carter_full_diary_nov26.txt"),
    }

    for name, alpha in sources.items():
        print(f"  {name}: {len(alpha)} alpha chars, {max(0, len(alpha) - N + 1)} windows")

    combined = ""
    for name in sorted(sources.keys()):
        combined += sources[name]
    sources["ALL_COMBINED"] = combined
    print(f"  ALL_COMBINED: {len(combined)} alpha chars, {max(0, len(combined) - N + 1)} windows")

    models = {
        "Vig": vigenere_decrypt,
        "Beau": beaufort_decrypt,
        "Quag": quagmire_decrypt,
    }

    # Transposition keywords
    trans_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "LATITUDE", "SANBORN", "CARTER", "HOWARD", "EGYPT",
        "TOMB", "PHARAOH", "TUTANKHAMUN", "CANDLE", "NECROPOLIS",
        "VALLEY", "THEBES", "LUXOR", "CARNARVON",
    ]

    all_candidates = []
    total_attempts = 0
    start_time = time.time()

    # ===== PHASE 1: Direct running key (no transposition) =====
    print("\n--- Phase 1: Direct running key ---")
    phase1_start = time.time()

    for src_name, alpha in sources.items():
        max_offset = len(alpha) - N
        if max_offset < 0:
            continue
        best_for_source = {"hits": 0}

        for model_name, decrypt_fn in models.items():
            for offset in range(max_offset + 1):
                key_window = alpha[offset:offset + N]
                pt = decrypt_fn(K4, key_window)
                total_attempts += 1

                a = anchor_score(pt)
                if a > best_for_source["hits"]:
                    best_for_source = {
                        "hits": a,
                        "model": model_name,
                        "offset": offset,
                        "pt_preview": pt[:60],
                    }
                if a >= 6:
                    e = english_bigram_score(pt)
                    vr = vowel_ratio(pt)
                    total = a * 40 + e * 3 + (15 if 0.30 <= vr <= 0.45 else 0)
                    all_candidates.append({
                        "phase": 1,
                        "score": total,
                        "anchor_hits": a,
                        "english_bigrams": e,
                        "vowel_ratio": round(vr, 3),
                        "model": model_name,
                        "source": src_name,
                        "transposition": None,
                        "offset": offset,
                        "key": key_window[:40] + "...",
                        "plaintext": pt,
                    })

        elapsed = time.time() - phase1_start
        print(f"  {src_name}: best {best_for_source['hits']}/24 "
              f"({best_for_source.get('model','?')} @{best_for_source.get('offset','?')})")

    phase1_elapsed = time.time() - phase1_start
    phase1_count = total_attempts
    print(f"  Phase 1 total: {phase1_count:,} attempts in {phase1_elapsed:.1f}s")
    print(f"  Candidates >= 6 hits: {len(all_candidates)}")

    # ===== PHASE 2: Transposition + running key =====
    print("\n--- Phase 2: Transposition + running key ---")
    phase2_start = time.time()

    # Only use the combined source for phase 2 to keep runtime bounded
    alpha = sources["ALL_COMBINED"]
    max_offset = len(alpha) - N

    best_trans = {"hits": 0}

    for kw in trans_keywords:
        perm = keyword_permutation(kw)
        ncols = len(kw)
        try:
            ct_t = columnar_decrypt(K4, ncols, perm)
        except Exception:
            continue

        kw_best = 0
        for model_name, decrypt_fn in models.items():
            for offset in range(max_offset + 1):
                key_window = alpha[offset:offset + N]
                pt = decrypt_fn(ct_t, key_window)
                total_attempts += 1

                a = anchor_score(pt)
                if a > kw_best:
                    kw_best = a
                if a > best_trans["hits"]:
                    best_trans = {
                        "hits": a, "kw": kw, "model": model_name,
                        "offset": offset, "pt": pt[:60],
                    }
                if a >= 8:
                    e = english_bigram_score(pt)
                    vr = vowel_ratio(pt)
                    total = a * 40 + e * 3 + (15 if 0.30 <= vr <= 0.45 else 0)
                    all_candidates.append({
                        "phase": 2,
                        "score": total,
                        "anchor_hits": a,
                        "english_bigrams": e,
                        "vowel_ratio": round(vr, 3),
                        "model": model_name,
                        "source": "ALL_COMBINED",
                        "transposition": kw,
                        "offset": offset,
                        "key": key_window[:40] + "...",
                        "plaintext": pt,
                    })

        elapsed_kw = time.time() - phase2_start
        print(f"  Keyword '{kw}': best {kw_best}/24 [{elapsed_kw:.1f}s elapsed]")

        # Time guard: stop after 5 minutes for phase 2
        if time.time() - phase2_start > 300:
            print(f"  Time limit reached, stopping phase 2")
            break

    phase2_elapsed = time.time() - phase2_start
    phase2_count = total_attempts - phase1_count
    print(f"  Phase 2 total: {phase2_count:,} attempts in {phase2_elapsed:.1f}s")

    # ===== PHASE 3: Reverse cipher direction =====
    print("\n--- Phase 3: Reverse direction (diary as ciphertext, K4 as key) ---")
    phase3_start = time.time()
    phase3_count_start = total_attempts

    # What if K4 isn't the ciphertext but acts as the KEY, and the diary
    # contains the ciphertext? This tests: decrypt(diary_window, K4)
    for src_name, alpha_src in sources.items():
        if src_name == "ALL_COMBINED":
            continue
        max_off = len(alpha_src) - N
        if max_off < 0:
            continue
        best_rev = 0
        for offset in range(max_off + 1):
            window = alpha_src[offset:offset + N]
            # Vigenere: P = C - K
            pt = vigenere_decrypt(window, K4)
            total_attempts += 1
            a = anchor_score(pt)
            if a > best_rev:
                best_rev = a
            if a >= 6:
                e = english_bigram_score(pt)
                all_candidates.append({
                    "phase": 3,
                    "score": a * 40 + e * 3,
                    "anchor_hits": a,
                    "model": "Vig_reverse",
                    "source": src_name,
                    "offset": offset,
                    "plaintext": pt,
                })
            # Beaufort reverse
            pt2 = beaufort_decrypt(window, K4)
            total_attempts += 1
            a2 = anchor_score(pt2)
            if a2 > best_rev:
                best_rev = a2
            if a2 >= 6:
                e2 = english_bigram_score(pt2)
                all_candidates.append({
                    "phase": 3,
                    "score": a2 * 40 + e2 * 3,
                    "anchor_hits": a2,
                    "model": "Beau_reverse",
                    "source": src_name,
                    "offset": offset,
                    "plaintext": pt2,
                })
        print(f"  {src_name} (reverse): best {best_rev}/24")

    phase3_elapsed = time.time() - phase3_start
    print(f"  Phase 3: {total_attempts - phase3_count_start:,} attempts in {phase3_elapsed:.1f}s")

    # ===== RESULTS =====
    elapsed = time.time() - start_time
    all_candidates.sort(key=lambda x: x["score"], reverse=True)

    print("\n" + "=" * 70)
    print(f"TOTAL: {total_attempts:,} attempts in {elapsed:.1f}s ({total_attempts/elapsed:,.0f}/s)")
    print(f"Candidates collected: {len(all_candidates)}")
    print("=" * 70)

    # Distribution of anchor hits
    from collections import Counter
    hit_dist = Counter(c["anchor_hits"] for c in all_candidates)
    print(f"\nAnchor hit distribution (candidates >= threshold):")
    for hits in sorted(hit_dist.keys(), reverse=True):
        print(f"  {hits}/24: {hit_dist[hits]} candidates")

    if all_candidates:
        print(f"\nTop 25 candidates:")
        seen = set()
        shown = 0
        for c in all_candidates:
            key = (c["anchor_hits"], c.get("model"), c.get("offset"), c.get("transposition"))
            if key in seen:
                continue
            seen.add(key)
            shown += 1
            print(f"\n  #{shown} | Score: {c['score']} | Anchors: {c['anchor_hits']}/24 "
                  f"| Bigrams: {c.get('english_bigrams', '?')}")
            print(f"       Phase: {c['phase']} | Model: {c['model']} | Source: {c['source']} "
                  f"| Trans: {c.get('transposition', '-')} | Offset: {c['offset']}")
            pt = c.get("plaintext", "")
            print(f"       PT: {pt[:80]}")
            # Highlight any readable fragments
            if c["anchor_hits"] >= 10:
                print(f"       FULL: {pt}")
            if shown >= 25:
                break
    else:
        print("\nNo candidates above threshold.")

    # ===== SAVE =====
    output = {
        "strategy_id": "39",
        "name": "Exhaustive Carter Journals Running-Key Attack",
        "sources": {k: len(v) for k, v in sources.items()},
        "total_attempts": total_attempts,
        "elapsed_seconds": round(elapsed, 1),
        "candidate_count": len(all_candidates),
        "top_candidates": [{k: v for k, v in c.items()} for c in all_candidates[:100]],
        "anchor_hit_distribution": dict(hit_dist),
    }
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "runs", "carter_journals_exhaustive.json",
    )
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
