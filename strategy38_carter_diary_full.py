"""Strategy 38: Full Carter Diary Running-Key Attack.

Tests every 97-character window from the actual November 26, 1922 Howard Carter
diary entry as a running key against K4 under Vigenere, Beaufort, and Quagmire III
cipher models. Also tests with transposition layer applied first.

This is the ACTUAL diary text from the Griffith Institute, not Sanborn's
paraphrased version in K3.
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
ANCHORS = [(c, int(d["start_index"]) - 1) for c, d in ANCHOR_COMPONENT_CLUES.items()]
KNOWN_PT = {}
for clue, start in ANCHORS:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

# 24 known positions
KNOWN_POSITIONS = sorted(KNOWN_PT.keys())

# ---------- load diary ----------
DIARY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "kryptos", "data", "corpora", "carter_full_diary_nov26.txt",
)
with open(DIARY_PATH, "r", encoding="utf-8") as f:
    raw_diary = f.read()

# Strip to alpha only
diary_alpha = re.sub(r"[^A-Za-z]", "", raw_diary).upper()
print(f"Diary alpha length: {len(diary_alpha)} characters")

# Also prepare K3's version for comparison
K3_FRAGMENT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART"
    "OFTHEDOORWAYWEREREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINXTHE"
    "HOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)


# ---------- cipher operations ----------
def vigenere_decrypt(ct: str, key: str) -> str:
    return "".join(
        chr((ord(c) - ord(k)) % 26 + 65) for c, k in zip(ct, key)
    )


def beaufort_decrypt(ct: str, key: str) -> str:
    return "".join(
        chr((ord(k) - ord(c)) % 26 + 65) for c, k in zip(ct, key)
    )


def quagmire_decrypt(ct: str, key: str, alphabet: str = KRYPTOS_ALPHABET) -> str:
    result = []
    for c, k in zip(ct, key):
        ci = alphabet.index(c) if c in alphabet else STANDARD_ALPHABET.index(c)
        ki = alphabet.index(k) if k in alphabet else STANDARD_ALPHABET.index(k)
        pi = (ci - ki) % 26
        result.append(STANDARD_ALPHABET[pi])
    return "".join(result)


def variant_beaufort_decrypt(ct: str, key: str) -> str:
    """Variant Beaufort: P = C - K mod 26 (same as Vigenere encrypt direction)."""
    return "".join(
        chr((ord(c) - ord(k)) % 26 + 65) for c, k in zip(ct, key)
    )


# ---------- transposition helpers ----------
def columnar_decrypt(ct: str, ncols: int, perm: list[int]) -> str:
    n = len(ct)
    nrows = (n + ncols - 1) // ncols
    full_cols = n % ncols or ncols
    col_lengths = [nrows if i < full_cols else nrows - 1 for i in range(ncols)]
    # Distribute ciphertext into columns in permutation order
    cols = [""] * ncols
    pos = 0
    for col_idx in perm:
        clen = col_lengths[col_idx]
        cols[col_idx] = ct[pos:pos + clen]
        pos += clen
    # Read off row by row
    result = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return "".join(result)


def keyword_permutation(keyword: str) -> list[int]:
    indexed = sorted(range(len(keyword)), key=lambda i: keyword[i])
    perm = [0] * len(keyword)
    for rank, idx in enumerate(indexed):
        perm[idx] = rank
    # Return order: which column comes first
    order = sorted(range(len(keyword)), key=lambda i: perm[i])
    return order


# ---------- scoring ----------
def anchor_score(plaintext: str) -> int:
    """Count how many of the 24 known positions match."""
    matches = 0
    for pos, expected in KNOWN_PT.items():
        if pos < len(plaintext) and plaintext[pos] == expected:
            matches += 1
    return matches


def english_score(text: str) -> float:
    """Simple bigram + common word scoring."""
    COMMON_BIGRAMS = {
        "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
        "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
        "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
        "VE", "CO", "ME", "DE", "HI", "RI", "RO", "IC", "NE", "EA",
    }
    COMMON_WORDS = {
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "HER",
        "WAS", "ONE", "OUR", "OUT", "HAS", "HIS", "HOW", "ITS", "MAY",
        "NEW", "NOW", "OLD", "SEE", "WAY", "WHO", "DID", "GET", "HIM",
        "LET", "SAY", "SHE", "TOO", "USE", "THIS", "THAT", "WITH",
        "HAVE", "FROM", "THEY", "BEEN", "SAID", "EACH", "WHICH",
        "THEIR", "WILL", "OTHER", "ABOUT", "THERE", "THESE", "THOSE",
        "WOULD", "COULD", "SHOULD", "AFTER", "BEFORE", "BETWEEN",
        "BERLIN", "CLOCK", "EAST", "NORTH", "NORTHEAST", "WEST",
    }
    score = 0.0
    for i in range(len(text) - 1):
        if text[i:i + 2] in COMMON_BIGRAMS:
            score += 1
    for w in COMMON_WORDS:
        if w in text:
            score += len(w) * 2
    # Vowel ratio
    vowels = sum(1 for c in text if c in "AEIOU")
    ratio = vowels / len(text) if text else 0
    if 0.30 <= ratio <= 0.45:
        score += 10
    return score


# ---------- main sweep ----------
def main():
    print("=" * 70)
    print("Strategy 38: Full Carter Diary Running-Key Attack")
    print("=" * 70)
    print(f"K4 ciphertext: {K4}")
    print(f"Known positions: {len(KNOWN_PT)} chars at {KNOWN_POSITIONS}")
    print()

    n = len(K4)
    assert n == 97

    cipher_models = {
        "Vigenere": vigenere_decrypt,
        "Beaufort": beaufort_decrypt,
        "Quagmire_III": lambda ct, key: quagmire_decrypt(ct, key, KRYPTOS_ALPHABET),
    }

    # Transposition keywords to try
    trans_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "LATITUDE", "SANBORN", "CARTER", "HOWARD", "EGYPT",
        "TOMB", "PHARAOH", "TUTANKHAMUN", "CANDLE",
    ]

    top_candidates = []
    total_attempts = 0
    start_time = time.time()

    # ---------- Phase 1: Direct running key (no transposition) ----------
    print("--- Phase 1: Direct running key from diary ---")
    max_offset = len(diary_alpha) - n
    if max_offset < 0:
        print("Diary too short for running key!")
        return

    for model_name, decrypt_fn in cipher_models.items():
        for offset in range(max_offset + 1):
            key_window = diary_alpha[offset:offset + n]
            pt = decrypt_fn(K4, key_window)
            total_attempts += 1

            a_score = anchor_score(pt)
            if a_score >= 4:  # At least 4 anchor chars match
                e_score = english_score(pt)
                total = a_score * 40 + e_score
                top_candidates.append({
                    "score": total,
                    "anchor_hits": a_score,
                    "english_score": e_score,
                    "model": model_name,
                    "transposition": None,
                    "diary_offset": offset,
                    "key_window": key_window[:30] + "...",
                    "plaintext": pt,
                    "diary_context": diary_alpha[max(0, offset - 10):offset + n + 10],
                })

    phase1_time = time.time() - start_time
    phase1_attempts = total_attempts
    print(f"  {phase1_attempts} attempts in {phase1_time:.1f}s")
    print(f"  Candidates with >= 4 anchor hits: {len(top_candidates)}")

    # ---------- Phase 2: Transposition + running key ----------
    print("\n--- Phase 2: Transposition inverse + running key from diary ---")
    phase2_start = time.time()

    for kw in trans_keywords:
        perm = keyword_permutation(kw)
        ncols = len(kw)
        try:
            ct_transposed = columnar_decrypt(K4, ncols, perm)
        except Exception:
            continue

        for model_name, decrypt_fn in cipher_models.items():
            for offset in range(max_offset + 1):
                key_window = diary_alpha[offset:offset + n]
                pt = decrypt_fn(ct_transposed, key_window)
                total_attempts += 1

                a_score = anchor_score(pt)
                if a_score >= 4:
                    e_score = english_score(pt)
                    total = a_score * 40 + e_score
                    top_candidates.append({
                        "score": total,
                        "anchor_hits": a_score,
                        "english_score": e_score,
                        "model": model_name,
                        "transposition": kw,
                        "diary_offset": offset,
                        "key_window": key_window[:30] + "...",
                        "plaintext": pt,
                    })

    phase2_time = time.time() - phase2_start
    print(f"  {total_attempts - phase1_attempts} attempts in {phase2_time:.1f}s")
    print(f"  Total candidates with >= 4 anchor hits: {len(top_candidates)}")

    # ---------- Phase 3: Compare K3 version vs actual diary ----------
    print("\n--- Phase 3: K3 paraphrase vs actual diary alignment ---")
    # Find where in the diary the K3 text aligns
    k3_alpha = K3_FRAGMENT.upper()
    # Compute alignment by looking for longest common substring
    diary_words_for_alignment = diary_alpha
    # Find "SLOWLYDESPARATLYSLOWLY" -> actual diary has different phrasing
    # Let's find where Sanborn diverged
    # K3 says: SLOWLYDESPARATLYSLOWLY...
    # Diary says: Find the matching section
    
    # Search for the "IMADEATINYBREACH" fragment in both
    k3_breach = "IMADEATINYBREACH"
    diary_breach_pos = diary_alpha.find("MADEATINYBREACH")
    k3_breach_pos = k3_alpha.find("IMADEATINYBREACH")
    
    print(f"  K3 paraphrase length: {len(k3_alpha)}")
    print(f"  Diary alpha length: {len(diary_alpha)}")
    if diary_breach_pos >= 0:
        print(f"  'MADEATINYBREACH' found in diary at position {diary_breach_pos}")
    if k3_breach_pos >= 0:
        print(f"  'IMADEATINYBREACH' found in K3 at position {k3_breach_pos}")
    
    # Show the differences
    print("\n  Key textual differences (K3 paraphrase vs actual diary):")
    # K3: "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS"
    # Diary: Different phrasing around this section
    # K3: "INSERTED THE CANDLE AND PEERED IN"  
    # Diary: "I WIDENED THE BREACH AND BY MEANS OF THE CANDLE LOOKED IN"
    # K3: "CAN YOU SEE ANYTHING"
    # Diary: "CAN YOU SEE ANYTHING" (same!)
    
    # Find the "CANYOUSEEANYTHING" in diary
    candle_pos = diary_alpha.find("CANYOUSEEANYTHING")
    print(f"  'CANYOUSEEANYTHING' in diary at pos {candle_pos}")
    if candle_pos >= 0:
        print(f"  Diary context: ...{diary_alpha[candle_pos-20:candle_pos+30]}...")

    # ---------- Phase 4: Test diary as running key starting from K3-parallel points ----------
    print("\n--- Phase 4: Targeted offsets near K3-parallel sections ---")
    phase4_start = time.time()
    
    # Key offsets: around the "breach" and "candle" sections
    interesting_offsets = set()
    for fragment in [
        "MADEATINYBREACH", "CANYOUSEEANYTHING", "HOTAIRESCAPING",
        "CANDLETOFLICKER", "CHAMBERCAUSED", "DOORWAY",
        "SLOWLYDESPERATELY", "FEVERISHLY", "TOPLEFTHANDCORNER",
        "WIDENED", "BREACH", "CANDLE", "FLICKER", "CHAMBER",
        "MIST", "WONDERFUL", "DARKNESS",
    ]:
        pos = diary_alpha.find(fragment)
        if pos >= 0:
            # Test a window around this position
            for delta in range(-50, 51):
                off = pos + delta
                if 0 <= off <= max_offset:
                    interesting_offsets.add(off)

    # Also test offsets where K3's text would align if the diary were the source
    print(f"  Testing {len(interesting_offsets)} targeted offsets")
    
    # Extended cipher models for targeted search
    extended_models = {
        **cipher_models,
        "Vigenere_reverse": lambda ct, key: vigenere_decrypt(key, ct),  # swap roles
    }
    
    for model_name, decrypt_fn in extended_models.items():
        for offset in sorted(interesting_offsets):
            key_window = diary_alpha[offset:offset + n]
            if len(key_window) < n:
                continue
            pt = decrypt_fn(K4, key_window)
            total_attempts += 1

            a_score = anchor_score(pt)
            if a_score >= 3:
                e_score = english_score(pt)
                total = a_score * 40 + e_score
                top_candidates.append({
                    "score": total,
                    "anchor_hits": a_score,
                    "english_score": e_score,
                    "model": model_name + "_targeted",
                    "transposition": None,
                    "diary_offset": offset,
                    "key_window": key_window[:30] + "...",
                    "plaintext": pt,
                })

    phase4_time = time.time() - phase4_start
    print(f"  Phase 4: {time.time() - phase4_start:.1f}s")

    # ---------- Results ----------
    elapsed = time.time() - start_time
    top_candidates.sort(key=lambda x: x["score"], reverse=True)

    print("\n" + "=" * 70)
    print(f"RESULTS: {total_attempts} total attempts in {elapsed:.1f}s")
    print(f"Candidates with anchor hits >= threshold: {len(top_candidates)}")
    print("=" * 70)

    if top_candidates:
        print("\nTop 20 candidates:")
        for i, c in enumerate(top_candidates[:20]):
            print(f"\n  #{i+1} | Score: {c['score']:.0f} | Anchors: {c['anchor_hits']}/24 | English: {c['english_score']:.1f}")
            print(f"       Model: {c['model']} | Trans: {c['transposition']} | Diary offset: {c['diary_offset']}")
            print(f"       Key: {c['key_window']}")
            print(f"       PT:  {c['plaintext'][:80]}")
    else:
        print("\nNo candidates found with sufficient anchor matches.")
        print("This suggests the Carter diary is NOT the running key source under")
        print("these cipher models, or a different transposition is needed.")

    # Save results
    output = {
        "strategy_id": "38",
        "name": "Full Carter Diary Running-Key Attack",
        "total_attempts": total_attempts,
        "elapsed_seconds": elapsed,
        "diary_length_alpha": len(diary_alpha),
        "cipher_models_tested": list(cipher_models.keys()),
        "transposition_keywords_tested": trans_keywords,
        "candidate_count": len(top_candidates),
        "top_candidates": [
            {k: v for k, v in c.items() if k != "diary_context"}
            for c in top_candidates[:50]
        ],
    }
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "runs", "carter_diary_full.json",
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
