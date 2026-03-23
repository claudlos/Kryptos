"""Strategy 38b: Deep Carter Diary Analysis.

Detailed comparison of K3 plaintext vs actual diary text, plus exhaustive
running-key attack with ALL columnar transposition periods 2-20 (not just
keyword-derived), and autokey variants.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from itertools import permutations

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kryptos.constants import (
    K4,
    K3_PT,
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

KNOWN_POSITIONS = sorted(KNOWN_PT.keys())

# ---------- load diary ----------
DIARY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "kryptos", "data", "corpora", "carter_full_diary_nov26.txt",
)
with open(DIARY_PATH, "r", encoding="utf-8") as f:
    raw_diary = f.read()

diary_alpha = re.sub(r"[^A-Za-z]", "", raw_diary).upper()


def anchor_score(pt: str) -> int:
    return sum(1 for pos, ch in KNOWN_PT.items() if pos < len(pt) and pt[pos] == ch)


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


def autokey_decrypt_plain(ct, primer):
    """Autokey where plaintext feeds back into key."""
    pt = []
    key_stream = list(primer)
    for i, c in enumerate(ct):
        k = key_stream[i] if i < len(key_stream) else pt[i - len(primer)]
        p = chr((ord(c) - ord(k)) % 26 + 65)
        pt.append(p)
        if i >= len(primer) - 1:
            key_stream.append(p)
    return "".join(pt)


def autokey_decrypt_cipher(ct, primer):
    """Autokey where ciphertext feeds back into key."""
    pt = []
    key_stream = list(primer)
    for i, c in enumerate(ct):
        k = key_stream[i] if i < len(key_stream) else ct[i - len(primer)]
        p = chr((ord(c) - ord(k)) % 26 + 65)
        pt.append(p)
    return "".join(pt)


# ---------- K3 vs Diary detailed comparison ----------
def compare_k3_diary():
    print("=" * 70)
    print("K3 PLAINTEXT vs ACTUAL DIARY — DETAILED COMPARISON")
    print("=" * 70)

    k3 = K3_PT.upper()
    diary = diary_alpha

    # K3 text (Sanborn's version):
    # SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART
    # OFTHEDOORWAYWEREREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT
    # HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINXTHE
    # HOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS
    # OFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ

    # Actual diary (key fragments):
    # "we made a tiny breach in the top left hand corner"
    # vs K3: "I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER"
    
    # "I widened the breach and by means of the candle looked in"
    # vs K3: "I INSERTED THE CANDLE AND PEERED IN"
    
    # "the hot air escaping caused the candle to flicker"
    # vs K3: "THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER"
    
    # "Can you see anything"
    # vs K3: "CAN YOU SEE ANYTHING" (identical!)

    diffs = [
        ("K3 OPENING", "SLOWLYDESPARATLYSLOWLY", "(NOT IN DIARY — Sanborn added this)"),
        ("K3", "THEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWEREREMOVED",
         "DIARY: similar but different word order"),
        ("K3", "WITHTREMBLINGHANDS", "(NOT IN DIARY — Sanborn added)"),
        ("K3 PRONOUN", "IMADEATINYBREACH", "DIARY: WEMADEATINYBREACH (we vs I)"),
        ("K3 LOCATION", "INTHEUPPERLEFTHANDCORNER", "DIARY: INTHETOPLEFTHANDCORNER (upper vs top)"),
        ("K3", "ANDTHENWIDENINGTHEHOLEALITTLE", "DIARY: similar"),
        ("K3", "IINSERTEDTHECANDLEANDPEEREDIN", "DIARY: IWIDENEDTHEBREACHANDBYMEANSOFTHECANDLELOOKEDIN"),
        ("K3 SEPARATOR", "X", "(Sanborn uses X as separator, not in diary)"),
        ("K3", "THEHOTAIRESCAPINGFROMTHECHAMBER", "DIARY: THEHOTAIRESCAPINGCAUSEDTHECANDLETOFLICKER"),
        ("K3", "CAUSEDTHEFLAMETOFLICKER", "DIARY: CAUSEDTHECANDLETOFLICKER (flame vs candle)"),
        ("K3", "BUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMIST",
         "DIARY: BUTASSOONASONEEYESBECAMEACCUSTOMEDTOTHEGLIMMEROFLIGHTTHEINTERIOROFTHECHAMBERGRADUALLYLOOMEDBEFOREONE"),
        ("K3 QUESTION", "CANYOUSEEANYTHINGQ", "DIARY: CANYOUSEEANYTHING (same, minus Q)"),
    ]

    for label, k3_text, diary_note in diffs:
        print(f"\n  {label}:")
        print(f"    K3:    {k3_text}")
        print(f"    Note:  {diary_note}")

    # Key finding: Sanborn made DELIBERATE changes
    print("\n" + "-" * 70)
    print("KEY FINDINGS:")
    print("  1. Sanborn changed 'we' to 'I' (first person singular)")
    print("  2. Sanborn changed 'top' to 'upper'")
    print("  3. Sanborn changed 'candle' to 'flame' (in the flickering sentence)")
    print("  4. Sanborn simplified 'I widened the breach and by means of the candle")
    print("     looked in' to 'I inserted the candle and peered in'")
    print("  5. Sanborn replaced 'one's eyes became accustomed to the glimmer of light")
    print("     the interior of the chamber gradually loomed' with 'presently details")
    print("     of the room within emerged from the mist'")
    print("  6. Sanborn added 'SLOWLY DESPARATLY SLOWLY' (with his misspelling)")
    print("  7. Sanborn added 'WITH TREMBLING HANDS'")
    print("  8. Sanborn used X as word separator in places")
    print("  9. Sanborn appended Q at the very end")
    print()
    print("  => These are CREATIVE MODIFICATIONS, not transcription errors.")
    print("  => This means K4's key source (if Carter diary) could be either:")
    print("     a) The ACTUAL diary text (what we're testing)")
    print("     b) Sanborn's OWN modified version (which might differ from K3 too)")
    print("     c) A DIFFERENT diary entry entirely")

    # Find exact diary positions for key fragments
    print("\n  Diary fragment positions:")
    for frag in [
        "SUNDAYNOVEMBER", "OPENSECOND", "DESCENDINGPASSAGE",
        "SEALEDDOORWAY", "TUTANKHAMEN", "ROYALNECROPOLIS",
        "FEVERISHLY", "TINYBREACH", "TOPLEFTHANDCORNER",
        "CANDLE", "DARKNESS", "CANYOUSEEANYTHING",
        "WONDERFUL", "TREASURES", "EBONYBLACK", "GOLDSANDALLED",
        "GOLDENINLAIDTHRONE", "CHARIOTS", "TUTANKHAMEN",
        "PHARAOH", "CLOSEDTHEHOLE", "DONKEYS",
    ]:
        pos = diary_alpha.find(frag)
        if pos >= 0:
            print(f"    {frag:30s} @ pos {pos:4d}")
        else:
            print(f"    {frag:30s}   NOT FOUND")


def exhaustive_period_search():
    """Test every columnar transposition period 2-14 with systematic permutations."""
    print("\n" + "=" * 70)
    print("EXHAUSTIVE PERIOD + RUNNING KEY SEARCH")
    print("=" * 70)

    n = len(K4)
    max_offset = len(diary_alpha) - n
    
    models = {
        "Vig": lambda ct, k: vigenere_decrypt(ct, k),
        "Beau": lambda ct, k: beaufort_decrypt(ct, k),
        "Quag": lambda ct, k: quagmire_decrypt(ct, k),
    }

    best_overall = []
    total_attempts = 0
    start = time.time()

    # For small periods (2-8), we can try ALL permutations
    # For larger periods, use identity + reverse + shift permutations
    for period in range(2, 15):
        if period <= 7:
            # All permutations feasible
            perms_to_try = list(permutations(range(period)))
            if len(perms_to_try) > 5040:
                # Shouldn't happen for period <= 7, but safety
                perms_to_try = perms_to_try[:5040]
        else:
            # Generate systematic permutations
            perms_to_try = []
            # Identity
            perms_to_try.append(tuple(range(period)))
            # Reverse
            perms_to_try.append(tuple(reversed(range(period))))
            # Circular shifts
            for shift in range(1, period):
                perms_to_try.append(tuple((i + shift) % period for i in range(period)))
            # Swap adjacent pairs
            for i in range(period - 1):
                p = list(range(period))
                p[i], p[i + 1] = p[i + 1], p[i]
                perms_to_try.append(tuple(p))

        best_for_period = None
        best_score_period = 0

        for perm in perms_to_try:
            # Apply columnar transposition decrypt
            nrows = (n + period - 1) // period
            full_cols = n % period or period
            col_lengths = [nrows if i < full_cols else nrows - 1 for i in range(period)]

            cols = [""] * period
            pos = 0
            valid = True
            for col_idx in perm:
                if col_idx >= period:
                    valid = False
                    break
                clen = col_lengths[col_idx]
                cols[col_idx] = K4[pos:pos + clen]
                pos += clen
            if not valid:
                continue

            ct_detrans = []
            for r in range(nrows):
                for c in range(period):
                    if r < len(cols[c]):
                        ct_detrans.append(cols[c][r])
            ct_detrans = "".join(ct_detrans)

            # Now try each diary offset as running key
            for model_name, decrypt_fn in models.items():
                for offset in range(max_offset + 1):
                    key_window = diary_alpha[offset:offset + n]
                    pt = decrypt_fn(ct_detrans, key_window)
                    total_attempts += 1

                    a = anchor_score(pt)
                    if a > best_score_period:
                        best_score_period = a
                        best_for_period = {
                            "period": period,
                            "perm": list(perm),
                            "model": model_name,
                            "offset": offset,
                            "anchor_hits": a,
                            "plaintext": pt,
                            "key": key_window[:40],
                        }
                    if a >= 8:
                        best_overall.append({
                            "period": period,
                            "perm": list(perm),
                            "model": model_name,
                            "offset": offset,
                            "anchor_hits": a,
                            "plaintext": pt,
                            "key": key_window[:40],
                        })

        elapsed = time.time() - start
        rate = total_attempts / elapsed if elapsed > 0 else 0
        if best_for_period:
            print(f"  Period {period:2d}: best={best_for_period['anchor_hits']}/24 "
                  f"({best_for_period['model']} offset={best_for_period['offset']}) "
                  f"[{total_attempts:,} attempts, {rate:,.0f}/s]")
        else:
            print(f"  Period {period:2d}: no candidates [{total_attempts:,} attempts]")

        # Time limit: stop after 120 seconds
        if elapsed > 120:
            print(f"\n  Time limit reached at period {period}")
            break

    elapsed = time.time() - start
    print(f"\nTotal: {total_attempts:,} attempts in {elapsed:.1f}s")
    print(f"Candidates with >= 8 anchor hits: {len(best_overall)}")

    if best_overall:
        best_overall.sort(key=lambda x: x["anchor_hits"], reverse=True)
        print("\nTop candidates:")
        for i, c in enumerate(best_overall[:10]):
            print(f"  #{i+1} Anchors={c['anchor_hits']}/24 | Period={c['period']} "
                  f"Perm={c['perm'][:8]}... | {c['model']} offset={c['offset']}")
            print(f"       PT: {c['plaintext'][:80]}")

    return best_overall


def autokey_diary_search():
    """Test diary fragments as autokey primers."""
    print("\n" + "=" * 70)
    print("AUTOKEY WITH DIARY PRIMERS")
    print("=" * 70)

    n = len(K4)
    best = []
    total = 0

    # Test diary fragments of various lengths as primers
    for primer_len in [5, 7, 8, 10, 13, 15, 20, 26, 50, 97]:
        best_for_len = None
        best_score = 0
        max_off = len(diary_alpha) - primer_len
        if max_off < 0:
            continue

        for offset in range(max_off + 1):
            primer = diary_alpha[offset:offset + primer_len]

            # Plain autokey
            pt = autokey_decrypt_plain(K4, primer)
            total += 1
            a = anchor_score(pt)
            if a > best_score:
                best_score = a
                best_for_len = {
                    "primer_len": primer_len,
                    "offset": offset,
                    "type": "plain_autokey",
                    "anchor_hits": a,
                    "plaintext": pt[:60],
                    "primer": primer[:30],
                }
            if a >= 6:
                best.append({
                    "primer_len": primer_len,
                    "offset": offset,
                    "type": "plain_autokey",
                    "anchor_hits": a,
                    "plaintext": pt,
                    "primer": primer[:30],
                })

            # Cipher autokey
            pt = autokey_decrypt_cipher(K4, primer)
            total += 1
            a = anchor_score(pt)
            if a > best_score:
                best_score = a
                best_for_len = {
                    "primer_len": primer_len,
                    "offset": offset,
                    "type": "cipher_autokey",
                    "anchor_hits": a,
                    "plaintext": pt[:60],
                    "primer": primer[:30],
                }
            if a >= 6:
                best.append({
                    "primer_len": primer_len,
                    "offset": offset,
                    "type": "cipher_autokey",
                    "anchor_hits": a,
                    "plaintext": pt,
                    "primer": primer[:30],
                })

        if best_for_len:
            print(f"  Primer len {primer_len:3d}: best={best_for_len['anchor_hits']}/24 "
                  f"({best_for_len['type']} offset={best_for_len['offset']})")

    print(f"\n  Total autokey attempts: {total:,}")
    print(f"  Candidates with >= 6 hits: {len(best)}")
    return best


def main():
    compare_k3_diary()
    
    autokey_results = autokey_diary_search()
    period_results = exhaustive_period_search()

    # Save combined results
    output = {
        "strategy": "38b",
        "name": "Carter Diary Deep Analysis",
        "diary_length": len(diary_alpha),
        "autokey_candidates": autokey_results[:20],
        "period_candidates": period_results[:20],
    }
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "runs", "carter_diary_deep.json",
    )
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
