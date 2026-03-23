"""Strategy 28: Digraphic Cipher Sweep.

Digraphic ciphers (Playfair, Four-square, Two-square, Bifid) process letter
PAIRS, which produces near-random Index of Coincidence — matching K4's
observed IC of ~0.036.  This sweep systematically tests all four families
with Kryptos-relevant keywords, optionally combined with LATITUDE
transposition, and scores candidates with both the standard anchor-first
scorer and a word-coverage scorer that catches real English missed by
bigram statistics.

Cipher families tested:
  1. Playfair (keyword squares, +LATITUDE transposition, +hill-climbing)
  2. Four-square (all keyword pairs)
  3. Two-square (horizontal + vertical, all keyword pairs)
  4. Bifid (periods 2-20, all keyword squares, +LATITUDE transposition)
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from itertools import combinations

sys.path.insert(0, ".")

from kryptos.constants import (
    K4,
    ANCHOR_COMPONENT_CLUES,
    POLYBIUS_ALPHABET,
    STANDARD_ALPHABET,
)
from kryptos.common import (
    build_score_breakdown,
    decrypt_bifid,
    generate_polybius_square,
    get_polybius_coordinates,
)
from kryptos.transposition import (
    keyword_permutation,
    periodic_transposition_decrypt,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
    "LATITUDE", "LONGITUDE", "SHADOW", "ILLUSION", "EGYPT",
    "CARTER", "LANGLEY", "SANBORN",
]

STANDARD_SQUARE = POLYBIUS_ALPHABET  # 25-char, no J

# Anchors from constants (1-indexed there, we use 0-indexed here)
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# LATITUDE transposition parameters (width = len("LATITUDE") = 8)
LATITUDE_WIDTH = 8
LATITUDE_PERM = keyword_permutation("LATITUDE", LATITUDE_WIDTH)

# ---------------------------------------------------------------------------
# Word-coverage scorer (~500 common English words, 3+ letters)
# ---------------------------------------------------------------------------
COMMON_WORDS = sorted({w for w in [
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN", "HER",
    "WAS", "ONE", "OUR", "OUT", "HAS", "HIS", "HOW", "MAN", "NEW", "NOW",
    "OLD", "SEE", "WAY", "WHO", "BOY", "DID", "ITS", "LET", "PUT", "SAY",
    "SHE", "TOO", "USE", "DAD", "MOM", "SET", "RUN", "GOT", "GET", "HIM",
    "HAD", "MAY", "DAY", "HAD", "HOT", "OIL", "SIT", "TOP", "RED", "TEN",
    "THAT", "WITH", "HAVE", "THIS", "WILL", "YOUR", "FROM", "THEY", "BEEN",
    "CALL", "COME", "EACH", "FIND", "FOUR", "GIVE", "GOOD", "JUST", "KNOW",
    "LIKE", "LINE", "LONG", "LOOK", "MADE", "MANY", "MORE", "MOST", "MUCH",
    "MUST", "NAME", "ONLY", "OVER", "PART", "SAID", "SOME", "SUCH", "TAKE",
    "TELL", "THAN", "THEM", "THEN", "TIME", "TURN", "USED", "VERY", "WANT",
    "WELL", "WENT", "WERE", "WHAT", "WHEN", "WILL", "WITH", "WORD", "WORK",
    "YEAR", "ALSO", "BACK", "BEEN", "CAME", "CITY", "EVEN", "HAND", "HEAD",
    "HERE", "HIGH", "HOME", "KEEP", "KIND", "LAND", "LAST", "LEFT", "LIFE",
    "LIVE", "MOVE", "NEAR", "NEED", "NEXT", "OPEN", "PLAY", "POINT", "READ",
    "REAL", "ROOM", "SAME", "SIDE", "SHOW", "TREE", "UNDER", "UPON", "WEST",
    "EAST", "NORTH", "SOUTH", "ABOUT", "ABOVE", "AFTER", "AGAIN", "BEING",
    "BELOW", "BETWEEN", "COULD", "EVERY", "FIRST", "FOUND", "GREAT", "HOUSE",
    "LARGE", "LEARN", "LIGHT", "MIGHT", "NIGHT", "NEVER", "OTHER", "PLACE",
    "PLANT", "RIGHT", "SHALL", "SINCE", "SMALL", "SOUND", "SPELL", "STAND",
    "STILL", "STORY", "THEIR", "THERE", "THESE", "THING", "THINK", "THREE",
    "WATER", "WHERE", "WHICH", "WHILE", "WORLD", "WOULD", "WRITE", "YOUNG",
    "BEFORE", "CHANGE", "DIFFER", "FOLLOW", "LITTLE", "MOTHER", "NUMBER",
    "PEOPLE", "SHOULD", "SIMPLE", "LETTER", "ANSWER", "ANIMAL", "AROUND",
    "BETTER", "CALLED", "CANNOT", "CENTER", "CHANGE", "COMMON", "COURSE",
    "DURING", "ENOUGH", "FAMILY", "FATHER", "FIGURE", "GROUND", "HAPPEN",
    "ITSELF", "MIDDLE", "MOMENT", "NOTICE", "PERSON", "PERIOD", "PLEASE",
    "SECOND", "SECRET", "SEEMS", "SYSTEM", "TOWARD", "TRAVEL", "TWELVE",
    "UNITED", "ACROSS", "ALMOST", "ALWAYS", "BECOME", "BEHIND", "BEYOND",
    "BROKEN", "BROUGHT", "CAUGHT", "CERTAIN", "DECIDED", "DELIVER",
    "BECAUSE", "BETWEEN", "THROUGH", "AGAINST", "ANOTHER", "COUNTRY",
    "GENERAL", "NOTHING", "PICTURE", "PROBLEM", "PRODUCT", "PROGRAM",
    "PROVIDE", "HOWEVER", "INCLUDE", "ALREADY", "BROUGHT", "BELIEVE",
    "COMPLETE", "CONSIDER", "CONTINUE", "DESCRIBE", "DEVELOP", "DIFFERENT",
    "DISCOVER", "DISTANCE", "EDUCATION", "ENGINEER", "EXAMPLE", "EXERCISE",
    "EXPECTED", "FAMILIAR", "FAVORITE", "FINISHED", "FOLLOWED", "TOGETHER",
    "POSITION", "POSSIBLE", "QUESTION", "REMEMBER", "SENTENCE", "SEPARATE",
    "SURPRISE", "THOUSAND", "IMPORTANT", "INTERESTED", "LISTENING",
    "NECESSARY", "PARAGRAPH", "SOMETHING", "SOMETIMES", "WONDERFUL",
    "BEAUTIFUL", "BEGINNING", "CAREFULLY", "CERTAINLY", "COMMUNITY",
    "CONDITION", "DIRECTION", "DISCOVERY", "EDUCATION", "EVERYBODY",
    "PRESIDENT", "REPRESENT", "SUDDENLY",
    # Kryptos-domain words
    "BERLIN", "CLOCK", "EAST", "NORTHEAST", "SHADOW", "ILLUSION", "EGYPT",
    "CARTER", "LANGLEY", "SANBORN", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    "LATITUDE", "LONGITUDE", "MESSAGE", "DELIVER", "CARRY", "SEND",
    "WALL", "ALEXANDERPLATZ", "REUNIFICATION", "CROWD", "TOMB", "HOWARD",
    "TUTANKHAMUN", "WORLD", "ZEITUHR", "BURIED", "INVISIBLE", "MAGNETIC",
    "FIELD", "INFORMATION", "GATHERED", "TRANSMITTED", "UNDERGROUND",
    "UNKNOWN", "LOCATION", "EXACT", "PASSAGE", "DEBRIS", "DOORWAY",
    "REMOVED", "TREMBLING", "BREACH", "CORNER", "WIDENING", "INSERTED",
    "CANDLE", "PEERED", "ESCAPING", "CHAMBER", "CAUSED", "FLAME",
    "FLICKER", "PRESENTLY", "DETAILS", "EMERGED", "SLOWLY", "DESPERATELY",
    "REMAINS", "ENCUMBERED", "LOWER", "UPPER", "LAYER", "CIPHER",
    "DECODE", "ENCRYPT", "DECRYPT", "SQUARE", "AGENCY", "CENTRAL",
    "INTELLIGENCE", "SCULPTURE", "COPPERPLATE", "MORSE", "CODE",
    "SECRET", "HIDDEN", "ANCIENT", "MODERN", "TEMPLE", "PYRAMID",
    "VALLEY", "KING", "QUEEN", "PHARAOH", "NILE", "GIZA", "LUXOR",
    "WEST", "DEGREE", "MINUTE", "SECOND", "NORTH", "SOUTH",
    "SEVEN", "EIGHT", "FIFTY", "FORTY", "THIRTY", "POINT", "FIVE",
    "COORDINATE", "MAGNETIC", "UNDERGROUND", "SOMEWHERE", "ANYTHING",
    "SUBTL", "SHADING", "ABSENCE", "NUANCE", "BETWEEN", "TOTALLY",
    "POSSIBLE", "EARTHS", "SURFACE", "GROUND", "WATER", "STONE",
    "METAL", "GLASS", "PAPER", "PAINT", "BLACK", "WHITE", "GREEN",
    "BROWN", "CLEAR", "DARK", "DEEP", "WIDE", "FLAT", "SHARP",
    "THICK", "THIN", "LONG", "SHORT", "HEAVY", "UNDER", "ABOVE",
    "BELOW", "INSIDE", "OUTSIDE", "FRONT", "RIGHT", "WRONG",
    "TRUTH", "FALSE", "POWER", "FORCE", "SPEED", "LEVEL", "SPACE",
    "EARTH", "RIVER", "OCEAN", "MOUNT", "CLOUD", "LIGHT", "NIGHT",
    "SOUND", "VOICE", "HEART", "BLOOD", "BRAIN", "NERVE", "FLESH",
    "TOWER", "BRIDGE", "CLOCK", "WATCH", "RADIO", "WIRE", "CABLE",
    "TRAIN", "PLANE", "SHIP", "BOAT", "CROSS", "GUIDE", "GUARD",
    "AGENT", "CHIEF", "DIRECTOR", "OFFICE", "BUILDING", "GROUND",
    "FLOOR", "STEEL", "IRON", "LEAD", "GOLD", "SILVER", "COPPER",
    "COVER", "SHEET", "BLOCK", "FRAME", "WHEEL", "CHAIN", "LOCK",
    "DOOR", "GATE", "WALL", "FENCE", "PATH", "ROAD", "TRACK",
    "TRAIL", "ROUTE", "MARCH", "DRIVE", "DRIFT", "FLOAT", "SLIDE",
    "CLIMB", "REACH", "TOUCH", "PRESS", "PULL", "PUSH", "HOLD",
    "CATCH", "THROW", "BREAK", "BUILD", "SHAPE", "FORM", "MARK",
    "SIGN", "FLAG", "POLE", "POST", "STAKE", "STAND", "TABLE",
    "CHAIR", "BENCH", "SHELF", "STACK", "STORE", "COUNT", "CHECK",
    "MATCH", "SOLVE", "PROVE", "GRANT", "CLAIM", "AWARD", "TRUST",
    "WORTH", "PRICE", "VALUE", "SENSE", "TASTE", "SMELL", "COLOR",
    "SIGHT", "DREAM", "SLEEP", "NIGHT", "STEEL", "STONE", "GLASS",
]}, key=lambda w: (-len(w), w))


def word_coverage_score(text: str) -> float:
    """Greedy longest-match word coverage.  Returns fraction [0.0, 1.0]."""
    text = text.upper()
    n = len(text)
    if n == 0:
        return 0.0
    covered = [False] * n
    pos = 0
    while pos < n:
        best_len = 0
        for word in COMMON_WORDS:
            wl = len(word)
            if wl <= best_len:
                continue  # words sorted desc by length
            if pos + wl <= n and text[pos:pos + wl] == word:
                best_len = wl
                break  # longest first in sorted list
        if best_len > 0:
            for k in range(pos, pos + best_len):
                covered[k] = True
            pos += best_len
        else:
            pos += 1
    return sum(covered) / n


# ---------------------------------------------------------------------------
# Playfair cipher
# ---------------------------------------------------------------------------
def _char_at(square: str, row: int, col: int) -> str:
    return square[row * 5 + col]


def _pos_in_square(char: str, square: str) -> tuple[int, int]:
    c = char.upper().replace("J", "I")
    idx = square.index(c)
    return idx // 5, idx % 5


def decrypt_playfair_pair(a: str, b: str, square: str) -> tuple[str, str]:
    """Decrypt one Playfair digraph."""
    r1, c1 = _pos_in_square(a, square)
    r2, c2 = _pos_in_square(b, square)
    if r1 == r2:
        # same row: shift LEFT (decrypt)
        return _char_at(square, r1, (c1 - 1) % 5), _char_at(square, r2, (c2 - 1) % 5)
    elif c1 == c2:
        # same column: shift UP (decrypt)
        return _char_at(square, (r1 - 1) % 5, c1), _char_at(square, (r2 - 1) % 5, c2)
    else:
        # rectangle: swap columns
        return _char_at(square, r1, c2), _char_at(square, r2, c1)


def decrypt_playfair(ciphertext: str, square: str) -> str:
    """Decrypt ciphertext with Playfair.  If odd length, last char passed through."""
    ct = ciphertext.upper().replace("J", "I")
    result = []
    i = 0
    while i + 1 < len(ct):
        p1, p2 = decrypt_playfair_pair(ct[i], ct[i + 1], square)
        result.append(p1)
        result.append(p2)
        i += 2
    if i < len(ct):
        result.append(ct[i])  # odd trailing character
    return "".join(result)


# ---------------------------------------------------------------------------
# Four-square cipher
# ---------------------------------------------------------------------------
def decrypt_foursquare(ciphertext: str, keyed_ur: str, keyed_ll: str) -> str:
    """Decrypt Four-square.

    Standard squares at upper-left and lower-right.
    Keyed squares at upper-right (keyed_ur) and lower-left (keyed_ll).

    For each cipher pair (a, b):
      - Find a in keyed_ur -> (r1, c1)
      - Find b in keyed_ll -> (r2, c2)
      - plain1 = standard_ul[r1][c2]  (same row as a, same col as b)
      - plain2 = standard_lr[r2][c1]  (same row as b, same col as a)
    """
    std = STANDARD_SQUARE
    ct = ciphertext.upper().replace("J", "I")
    result = []
    i = 0
    while i + 1 < len(ct):
        r1, c1 = _pos_in_square(ct[i], keyed_ur)
        r2, c2 = _pos_in_square(ct[i + 1], keyed_ll)
        result.append(_char_at(std, r1, c2))
        result.append(_char_at(std, r2, c1))
        i += 2
    if i < len(ct):
        result.append(ct[i])
    return "".join(result)


# ---------------------------------------------------------------------------
# Two-square cipher
# ---------------------------------------------------------------------------
def decrypt_twosquare_horizontal(ciphertext: str, sq1: str, sq2: str) -> str:
    """Horizontal Two-square decrypt.

    Two keyed squares placed side by side.  Cipher pair (a, b):
      a looked up in sq1 (left), b in sq2 (right).
      If same row: plain = sq1[r1,c2], sq2[r2,c1]  (rectangle)
      If different rows: swap rows -> sq1[r2,c1], sq2[r1,c2]  — no, rectangle rule.
    Actually for two-square, same-row means just swap columns within respective squares,
    different rows means rectangle swap.
    """
    ct = ciphertext.upper().replace("J", "I")
    result = []
    i = 0
    while i + 1 < len(ct):
        r1, c1 = _pos_in_square(ct[i], sq1)
        r2, c2 = _pos_in_square(ct[i + 1], sq2)
        if r1 == r2:
            # same row: plain pair is at same row, swapped cols
            result.append(_char_at(sq1, r1, c2))
            result.append(_char_at(sq2, r2, c1))
        else:
            # rectangle
            result.append(_char_at(sq1, r2, c1))
            result.append(_char_at(sq2, r1, c2))
        i += 2
    if i < len(ct):
        result.append(ct[i])
    return "".join(result)


def decrypt_twosquare_vertical(ciphertext: str, sq_top: str, sq_bot: str) -> str:
    """Vertical Two-square decrypt.

    Two keyed squares stacked vertically.  Cipher pair (a, b):
      a looked up in sq_top, b in sq_bot.
      Same column: swap rows.  Different columns: rectangle.
    """
    ct = ciphertext.upper().replace("J", "I")
    result = []
    i = 0
    while i + 1 < len(ct):
        r1, c1 = _pos_in_square(ct[i], sq_top)
        r2, c2 = _pos_in_square(ct[i + 1], sq_bot)
        if c1 == c2:
            # same column: swap rows
            result.append(_char_at(sq_top, r2, c1))
            result.append(_char_at(sq_bot, r1, c2))
        else:
            # rectangle
            result.append(_char_at(sq_top, r1, c2))
            result.append(_char_at(sq_bot, r2, c1))
        i += 2
    if i < len(ct):
        result.append(ct[i])
    return "".join(result)


# ---------------------------------------------------------------------------
# LATITUDE transposition (inverse)
# ---------------------------------------------------------------------------
def undo_latitude_transposition(ciphertext: str) -> str:
    """Undo LATITUDE columnar transposition (decrypt the transposition layer)."""
    return periodic_transposition_decrypt(
        ciphertext, LATITUDE_WIDTH, LATITUDE_PERM
    )


# ---------------------------------------------------------------------------
# Combined scorer
# ---------------------------------------------------------------------------
def score_candidate(text: str) -> dict:
    """Return combined score dict with both standard and word-coverage scores."""
    breakdown = build_score_breakdown(text)
    wc = word_coverage_score(text)
    combined = breakdown["total"] + int(wc * 300)
    return {
        "text": text,
        "standard_total": breakdown["total"],
        "anchor": breakdown["anchor"],
        "language": breakdown["language"],
        "word_coverage": round(wc, 4),
        "combined": combined,
        "breakdown": breakdown,
    }


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
class ResultTracker:
    """Keep top-N results sorted by combined score."""

    def __init__(self, max_results: int = 200):
        self.results: list[dict] = []
        self.max_results = max_results
        self.total_tested = 0
        self.min_score = 0

    def add(self, cipher_type: str, params: str, text: str, score_info: dict):
        self.total_tested += 1
        combined = score_info["combined"]
        if combined < self.min_score and len(self.results) >= self.max_results:
            return
        entry = {
            "cipher": cipher_type,
            "params": params,
            "text": text[:97],
            "standard_total": score_info["standard_total"],
            "anchor": score_info["anchor"],
            "language": score_info["language"],
            "word_coverage": score_info["word_coverage"],
            "combined": combined,
        }
        self.results.append(entry)
        self.results.sort(key=lambda r: -r["combined"])
        if len(self.results) > self.max_results:
            self.results = self.results[:self.max_results]
            self.min_score = self.results[-1]["combined"]

    def top(self, n: int = 20) -> list[dict]:
        return self.results[:n]


# ---------------------------------------------------------------------------
# Phase 1: Playfair sweep
# ---------------------------------------------------------------------------
def run_playfair_sweep(tracker: ResultTracker):
    print("\n=== Phase 1: Playfair Cipher Sweep ===")
    ct = K4.replace("J", "I")

    # 1a. Direct Playfair with each keyword square
    print("  [1a] Direct Playfair with keyword squares...")
    for kw in KEYWORDS:
        sq = generate_polybius_square(kw)
        pt = decrypt_playfair(ct, sq)
        sc = score_candidate(pt)
        tracker.add("Playfair", f"keyword={kw}", pt, sc)

    # 1b. Playfair after undoing LATITUDE transposition
    print("  [1b] Playfair after LATITUDE transposition inverse...")
    ct_detrans = undo_latitude_transposition(ct)
    for kw in KEYWORDS:
        sq = generate_polybius_square(kw)
        pt = decrypt_playfair(ct_detrans, sq)
        sc = score_candidate(pt)
        tracker.add("Playfair+LatTrans", f"keyword={kw}", pt, sc)

    # 1c. Hill-climbing with Polybius square mutations
    print("  [1c] Hill-climbing Playfair (mutated squares)...")
    random.seed(42)
    best_per_kw: dict[str, tuple[int, str, str]] = {}

    for kw in KEYWORDS:
        base_sq = generate_polybius_square(kw)
        pt = decrypt_playfair(ct, base_sq)
        sc = score_candidate(pt)
        best_score = sc["combined"]
        best_sq = base_sq
        best_pt = pt

        # Try mutations
        for mutation_round in range(200):
            # Swap 2 random positions in the square
            chars = list(best_sq)
            i1, i2 = random.sample(range(25), 2)
            chars[i1], chars[i2] = chars[i2], chars[i1]
            trial_sq = "".join(chars)
            trial_pt = decrypt_playfair(ct, trial_sq)
            trial_sc = score_candidate(trial_pt)
            if trial_sc["combined"] > best_score:
                best_score = trial_sc["combined"]
                best_sq = trial_sq
                best_pt = trial_pt

        sc = score_candidate(best_pt)
        tracker.add("Playfair-HC", f"seed={kw} sq={best_sq[:10]}...", best_pt, sc)
        best_per_kw[kw] = (best_score, best_sq, best_pt)

    # Also try hill-climbing on LATITUDE-detransposed text
    print("  [1c+] Hill-climbing Playfair on LATITUDE-detransposed text...")
    for kw in KEYWORDS[:5]:  # top 5 keywords to limit time
        base_sq = generate_polybius_square(kw)
        pt = decrypt_playfair(ct_detrans, base_sq)
        sc = score_candidate(pt)
        best_score = sc["combined"]
        best_sq = base_sq
        best_pt = pt

        for mutation_round in range(150):
            chars = list(best_sq)
            i1, i2 = random.sample(range(25), 2)
            chars[i1], chars[i2] = chars[i2], chars[i1]
            trial_sq = "".join(chars)
            trial_pt = decrypt_playfair(ct_detrans, trial_sq)
            trial_sc = score_candidate(trial_pt)
            if trial_sc["combined"] > best_score:
                best_score = trial_sc["combined"]
                best_sq = trial_sq
                best_pt = trial_pt

        sc = score_candidate(best_pt)
        tracker.add("Playfair-HC+LatTrans", f"seed={kw}", best_pt, sc)

    tested = tracker.total_tested
    print(f"  Playfair phase complete: {tested} candidates tested")


# ---------------------------------------------------------------------------
# Phase 2: Four-square sweep
# ---------------------------------------------------------------------------
def run_foursquare_sweep(tracker: ResultTracker):
    print("\n=== Phase 2: Four-Square Cipher Sweep ===")
    ct = K4.replace("J", "I")

    # Build all keyword squares
    squares = {kw: generate_polybius_square(kw) for kw in KEYWORDS}

    # 2a. All keyword pairs
    print("  [2a] Four-square with all keyword pairs...")
    count = 0
    for kw1, kw2 in combinations(KEYWORDS, 2):
        sq1 = squares[kw1]
        sq2 = squares[kw2]
        # Try both orderings
        for sq_ur, sq_ll, label in [
            (sq1, sq2, f"UR={kw1},LL={kw2}"),
            (sq2, sq1, f"UR={kw2},LL={kw1}"),
        ]:
            pt = decrypt_foursquare(ct, sq_ur, sq_ll)
            sc = score_candidate(pt)
            tracker.add("Four-square", label, pt, sc)
            count += 1

    # 2b. Same keyword for both keyed squares
    print("  [2b] Four-square with same keyword for both squares...")
    for kw in KEYWORDS:
        sq = squares[kw]
        pt = decrypt_foursquare(ct, sq, sq)
        sc = score_candidate(pt)
        tracker.add("Four-square", f"UR=LL={kw}", pt, sc)
        count += 1

    # 2c. Four-square after LATITUDE transposition
    print("  [2c] Four-square after LATITUDE transposition...")
    ct_detrans = undo_latitude_transposition(ct)
    for kw1, kw2 in combinations(KEYWORDS[:7], 2):  # subset for time
        sq1 = squares[kw1]
        sq2 = squares[kw2]
        for sq_ur, sq_ll, label in [
            (sq1, sq2, f"UR={kw1},LL={kw2}+LatTrans"),
            (sq2, sq1, f"UR={kw2},LL={kw1}+LatTrans"),
        ]:
            pt = decrypt_foursquare(ct_detrans, sq_ur, sq_ll)
            sc = score_candidate(pt)
            tracker.add("Four-square+LatTrans", label, pt, sc)
            count += 1

    print(f"  Four-square phase complete: {count} additional candidates")


# ---------------------------------------------------------------------------
# Phase 3: Two-square sweep
# ---------------------------------------------------------------------------
def run_twosquare_sweep(tracker: ResultTracker):
    print("\n=== Phase 3: Two-Square Cipher Sweep ===")
    ct = K4.replace("J", "I")

    squares = {kw: generate_polybius_square(kw) for kw in KEYWORDS}

    count = 0
    # 3a. Horizontal two-square
    print("  [3a] Horizontal Two-square with all keyword pairs...")
    for kw1, kw2 in combinations(KEYWORDS, 2):
        sq1 = squares[kw1]
        sq2 = squares[kw2]
        for s1, s2, label in [
            (sq1, sq2, f"H:L={kw1},R={kw2}"),
            (sq2, sq1, f"H:L={kw2},R={kw1}"),
        ]:
            pt = decrypt_twosquare_horizontal(ct, s1, s2)
            sc = score_candidate(pt)
            tracker.add("Two-square-H", label, pt, sc)
            count += 1

    # 3b. Vertical two-square
    print("  [3b] Vertical Two-square with all keyword pairs...")
    for kw1, kw2 in combinations(KEYWORDS, 2):
        sq1 = squares[kw1]
        sq2 = squares[kw2]
        for s1, s2, label in [
            (sq1, sq2, f"V:T={kw1},B={kw2}"),
            (sq2, sq1, f"V:T={kw2},B={kw1}"),
        ]:
            pt = decrypt_twosquare_vertical(ct, s1, s2)
            sc = score_candidate(pt)
            tracker.add("Two-square-V", label, pt, sc)
            count += 1

    # 3c. Same keyword both squares
    print("  [3c] Two-square with same keyword...")
    for kw in KEYWORDS:
        sq = squares[kw]
        pt_h = decrypt_twosquare_horizontal(ct, sq, sq)
        sc_h = score_candidate(pt_h)
        tracker.add("Two-square-H", f"H:L=R={kw}", pt_h, sc_h)
        pt_v = decrypt_twosquare_vertical(ct, sq, sq)
        sc_v = score_candidate(pt_v)
        tracker.add("Two-square-V", f"V:T=B={kw}", pt_v, sc_v)
        count += 2

    # 3d. Two-square after LATITUDE transposition
    print("  [3d] Two-square after LATITUDE transposition...")
    ct_detrans = undo_latitude_transposition(ct)
    for kw1, kw2 in combinations(KEYWORDS[:7], 2):
        sq1 = squares[kw1]
        sq2 = squares[kw2]
        pt_h = decrypt_twosquare_horizontal(ct_detrans, sq1, sq2)
        sc_h = score_candidate(pt_h)
        tracker.add("Two-square-H+LatTrans", f"H:L={kw1},R={kw2}", pt_h, sc_h)
        pt_v = decrypt_twosquare_vertical(ct_detrans, sq1, sq2)
        sc_v = score_candidate(pt_v)
        tracker.add("Two-square-V+LatTrans", f"V:T={kw1},B={kw2}", pt_v, sc_v)
        count += 2

    print(f"  Two-square phase complete: {count} additional candidates")


# ---------------------------------------------------------------------------
# Phase 4: Bifid sweep
# ---------------------------------------------------------------------------
def run_bifid_sweep(tracker: ResultTracker):
    print("\n=== Phase 4: Bifid Cipher Sweep ===")
    ct = K4.replace("J", "I")

    squares = {kw: generate_polybius_square(kw) for kw in KEYWORDS}

    count = 0
    # 4a. Direct Bifid
    print("  [4a] Bifid with periods 2-20, all keyword squares...")
    for kw in KEYWORDS:
        sq = squares[kw]
        for period in range(2, 21):
            pt = decrypt_bifid(period, ct, sq)
            sc = score_candidate(pt)
            tracker.add("Bifid", f"keyword={kw},period={period}", pt, sc)
            count += 1

    # 4b. Bifid after LATITUDE transposition
    print("  [4b] Bifid after LATITUDE transposition...")
    ct_detrans = undo_latitude_transposition(ct)
    for kw in KEYWORDS:
        sq = squares[kw]
        for period in range(2, 21):
            pt = decrypt_bifid(period, ct_detrans, sq)
            sc = score_candidate(pt)
            tracker.add("Bifid+LatTrans", f"keyword={kw},period={period}", pt, sc)
            count += 1

    # 4c. Bifid with full-length period (= length of text, classic Bifid)
    print("  [4c] Bifid with period = len(K4) (full-length)...")
    for kw in KEYWORDS:
        sq = squares[kw]
        pt = decrypt_bifid(len(ct), ct, sq)
        sc = score_candidate(pt)
        tracker.add("Bifid-full", f"keyword={kw},period={len(ct)}", pt, sc)
        count += 1

    print(f"  Bifid phase complete: {count} additional candidates")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 72)
    print("Strategy 28: Digraphic Cipher Sweep")
    print("=" * 72)
    print(f"K4 ciphertext ({len(K4)} chars): {K4}")
    print(f"Keywords: {', '.join(KEYWORDS)}")
    print(f"Anchors: {ANCHORS}")
    print()

    t0 = time.time()
    tracker = ResultTracker(max_results=200)

    run_playfair_sweep(tracker)
    run_foursquare_sweep(tracker)
    run_twosquare_sweep(tracker)
    run_bifid_sweep(tracker)

    elapsed = time.time() - t0

    # Print top results
    print("\n" + "=" * 72)
    print(f"RESULTS: {tracker.total_tested} total candidates in {elapsed:.1f}s")
    print("=" * 72)

    top = tracker.top(30)
    print(f"\nTop {len(top)} candidates by combined score:\n")
    for rank, r in enumerate(top, 1):
        print(f"  #{rank:3d} | combined={r['combined']:4d} | std={r['standard_total']:4d} | "
              f"anchor={r['anchor']:4d} | lang={r['language']:3d} | "
              f"wc={r['word_coverage']:.3f} | {r['cipher']:22s} | {r['params']}")
        print(f"        | {r['text']}")
        print()

    # Check for anchor hits
    print("\n--- Anchor analysis on top 10 ---")
    for rank, r in enumerate(top[:10], 1):
        txt = r["text"]
        print(f"  #{rank} {r['cipher']} ({r['params']}):")
        for clue, start in ANCHORS:
            segment = txt[start:start + len(clue)] if start + len(clue) <= len(txt) else "???"
            match_chars = sum(1 for a, b in zip(segment, clue) if a == b)
            print(f"    {clue:>9s}@{start}: got '{segment}' ({match_chars}/{len(clue)} chars)")
        print()

    # Save results
    output = {
        "strategy": "28_digraphic_sweep",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": round(elapsed, 2),
        "total_candidates_tested": tracker.total_tested,
        "k4_length": len(K4),
        "keywords_used": KEYWORDS,
        "anchors": [{"clue": c, "start_0idx": s} for c, s in ANCHORS],
        "top_results": tracker.top(50),
    }

    os.makedirs("runs", exist_ok=True)
    outpath = "runs/digraphic_sweep.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")
    print(f"Total candidates tested: {tracker.total_tested}")
    print(f"Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
