#!/usr/bin/env python3
"""Strategy 35: No-Transposition Quagmire III Deep Search.

K1 and K2 were both encrypted with Quagmire III using the KRYPTOS mixed
alphabet and specific keywords. This strategy tests K4 as a PURE Quagmire III
cipher (no transposition) exhaustively over a large keyword list, key offsets,
and position offsets.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, ".")

from kryptos.constants import (
    K4,
    KRYPTOS_ALPHABET,
    ANCHOR_COMPONENT_CLUES,
)
from kryptos.common import (
    build_quagmire_tableau,
    decrypt_quagmire_running,
    build_score_breakdown,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STRATEGY_ID = 35
STRATEGY_NAME = "No-Transposition Quagmire III Deep Search"
OUTPUT_FILE = os.path.join("runs", "pure_quagmire.json")

# Anchors (0-indexed):  EAST@21-24, NORTHEAST@25-33, BERLIN@63-68, CLOCK@69-73
ANCHORS = [
    ("EAST",      21, 25),
    ("NORTHEAST", 25, 34),
    ("BERLIN",    63, 69),
    ("CLOCK",     69, 74),
]

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN",
    "SHADOW", "ILLUSION", "EGYPT", "CARTER", "LANGLEY", "LATITUDE",
    "LONGITUDE", "DEGREES", "MINUTES", "SECONDS", "POSITION", "NORTHEAST",
    "EAST", "HIDDEN", "LUCENT", "MESSAGE", "TOMB", "HOWARD", "TREASURE",
    "SECRET", "ANCIENT", "DISCOVERY", "PASSAGE", "CHAMBER", "TUNNEL",
    "CORRIDOR", "DESERT", "TEMPLE", "PYRAMID", "VALLEY", "NILE", "PHARAOH",
    "INFORMATION", "MAGNETIC", "FIELD", "INVISIBLE", "UNDERGROUND",
    "LOCATION", "IQLUSION", "DESPERATELY", "SLOWLY", "REMAINS", "DEBRIS",
    "TREMBLING", "CANDLE", "FLICKER", "EMERGED",
]

# ~500-word embedded dictionary for greedy word-coverage scoring
DICTIONARY = sorted({
    # Common English
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN", "HER",
    "WAS", "ONE", "OUR", "OUT", "HAS", "HIS", "HOW", "ITS", "MAY", "NEW",
    "NOW", "OLD", "SEE", "WAY", "WHO", "DID", "GET", "HIM", "LET", "SAY",
    "SHE", "TOO", "USE", "DAD", "MOM", "RUN", "SET", "TRY", "ASK", "MEN",
    "READ", "NEED", "LAND", "HERE", "MUST", "HOME", "LONG", "MAKE", "MUCH",
    "NAME", "ONLY", "OVER", "SUCH", "TAKE", "THAN", "THEM", "THEN", "VERY",
    "WHEN", "COME", "EACH", "HAVE", "JUST", "KNOW", "LIKE", "BEEN", "CALL",
    "FIND", "FROM", "GIVE", "GOOD", "HAND", "HIGH", "KEEP", "LAST", "LOOK",
    "MADE", "MANY", "MORE", "MOST", "MOVE", "NEXT", "PART", "SAID", "SAME",
    "SOME", "TELL", "THAT", "THEY", "THIS", "TIME", "TURN", "USED", "WANT",
    "WELL", "WENT", "WHAT", "WILL", "WITH", "WORD", "WORK", "YEAR", "ALSO",
    "BACK", "BEEN", "CITY", "CAME", "DOWN", "EVEN", "FACE", "FELT", "FOUR",
    "FULL", "GAVE", "GONE", "HALF", "HEAD", "HELP", "IDEA", "INTO", "KIND",
    "LEFT", "LIFE", "LINE", "LIVE", "MARK", "NEAR", "OPEN", "PLAY", "REAL",
    "ROOM", "SEEM", "SHOW", "SIDE", "STOP", "SURE", "TALK", "TOLD", "TRUE",
    "UPON", "WEEK", "BEST", "BODY", "BOOK", "BOTH", "CASE", "DARK", "DEEP",
    "DOES", "DONE", "DOOR", "DRAW", "DROP", "ELSE", "EVER", "FACT", "FALL",
    "FEAR", "FEEL", "FILL", "FIVE", "FOOD", "FOOT", "FORM", "FREE", "GIRL",
    "GROW", "HARD", "HEAR", "HOLD", "HOPE", "HOUR", "JUST", "KING", "KNEW",
    "LATE", "LESS", "LIST", "LOST", "LOVE", "MEAN", "MEET", "MIND", "MISS",
    "NORTH", "SOUTH", "EAST", "WEST",
    "ABOUT", "AFTER", "AGAIN", "BEING", "BELOW", "EVERY", "FIRST", "FOUND",
    "GREAT", "HOUSE", "LARGE", "LATER", "LEARN", "NEVER", "NIGHT", "ORDER",
    "OTHER", "PLACE", "PLANT", "POINT", "RIGHT", "SHALL", "SINCE", "SMALL",
    "SOUND", "STILL", "STUDY", "THEIR", "THERE", "THESE", "THING", "THINK",
    "THREE", "TIMES", "UNDER", "WATER", "WHERE", "WHICH", "WHILE", "WORLD",
    "WOULD", "WRITE", "ABOVE", "ALONG", "BEGIN", "BLACK", "BROWN", "BUILD",
    "CARRY", "CATCH", "CAUSE", "CHILD", "CLOSE", "COULD", "COVER", "CROSS",
    "EARTH", "EIGHT", "GLASS", "GREEN", "GROUP", "HEARD", "HORSE", "LIGHT",
    "MIGHT", "MONEY", "MONTH", "OFTEN", "PAPER", "PIECE", "POWER", "PRESS",
    "QUICK", "QUITE", "REACH", "RIVER", "ROUND", "SEVEN", "SHORT", "SHOWN",
    "SLEEP", "SPACE", "STAND", "START", "STATE", "STONE", "STORY", "TABLE",
    "THOSE", "TODAY", "UNTIL", "USUAL", "VOICE", "WATCH", "WHITE", "WHOLE",
    "WOMAN", "YOUNG",
    "BEFORE", "BETTER", "CHANGE", "DURING", "FIGURE", "FOLLOW",
    "GROUND", "HAPPEN", "ISLAND", "LETTER", "LITTLE", "LIVING", "MOTHER",
    "MOVING", "NUMBER", "PEOPLE", "PERSON", "PICTUQE", "RECORD", "RESULT",
    "SECOND", "SHOULD", "SIMPLE", "SOCIAL", "STRONG", "SYSTEM", "TOWARD",
    "TRAVEL", "WITHIN",
    "BETWEEN", "COUNTRY", "EXAMPLE", "GENERAL", "HOWEVER", "HUNDRED",
    "MESSAGE", "MILLION", "MORNING", "NOTHING", "PICTURE", "PROBLEM",
    "PROGRAM", "SEVERAL", "THOUGHT", "THROUGH", "TURNING", "WITHOUT",
    # Kryptos / Egypt / Berlin domain terms
    "BERLIN", "CLOCK", "SHADOW", "HIDDEN", "SECRET", "PASSAGE",
    "CHAMBER", "TUNNEL", "CORRIDOR", "DESERT", "TEMPLE", "PYRAMID",
    "VALLEY", "NILE", "PHARAOH", "TOMB", "EGYPT", "TREASURE", "ANCIENT",
    "DISCOVERY", "POSITION", "LATITUDE", "LONGITUDE", "DEGREES", "MINUTES",
    "SECONDS", "NORTHEAST", "MAGNETIC", "FIELD", "INVISIBLE", "UNDERGROUND",
    "LOCATION", "INFORMATION", "ILLUSION", "IQLUSION", "CANDLE", "FLICKER",
    "EMERGED", "REMAINS", "DEBRIS", "TREMBLING", "DESPERATELY", "SLOWLY",
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "LANGLEY",
    "WALL", "ALEXANDERPLATZ", "CROWD", "REUNIFICATION",
    "CIPHER", "DECODE", "ENCRYPT", "PLAINTEXT", "ALPHABET",
    "HOWARD", "CARTER", "LUCENT", "KING",
    "ENTRANCE", "OPENING", "SEALED", "GOLDEN", "ROYAL", "BURIAL",
    "ARTIFACT", "STATUE", "INSCRIPTION", "HIEROGLYPH",
    "OBELISK", "SPHINX", "LUXOR", "GIZA", "KARNAK", "THEBES",
    "EXCAVATION", "ARCHAEOLOGY", "EXPEDITION",
    "COORDINATE", "BEARING", "AZIMUTH", "HEADING",
    "THIRTEEN", "FOURTEEN", "FIFTEEN", "SIXTEEN", "SEVENTEEN", "EIGHTEEN",
    "NINETEEN", "TWENTY", "THIRTY", "FORTY", "FIFTY", "SIXTY", "SEVENTY",
    "EIGHTY", "NINETY",
    "WORLD", "SIGNAL", "TRANSMIT", "RECEIVE", "AGENT", "COVERT",
    "MISSION", "OPERATION", "INTELLIGENCE", "AGENCY",
    "DELIVER", "MESSAGE", "CARRY", "SEND",
    "DOOR", "DOORWAY", "BREACH", "UPPER", "LOWER", "CORNER",
    "HAND", "HANDS", "WIDENING", "HOLE", "INSERTED", "PEERED",
    "FLAME", "ESCAPING", "DETAIL", "DETAILS", "MIST",
    "REMOVED", "ENCUMBERED", "PRESENTLY",
    "CAN", "SEE", "ANYTHING",
    "HOT", "AIR", "TINY", "LEFT", "RIGHT",
    "LAYER", "TWO", "ONE", "SIX", "TEN",
    "WAS", "HIS", "HAD", "HAS", "WERE", "BEEN",
    "INTO", "WITH", "FROM", "THEY", "THEM", "THAN", "EACH",
    "ALEXANDERPLATZ", "ZEITUHR",
    "POINT", "EXACT", "SOMEWHERE", "BURIED", "UNKNOWN",
    "TOTALLY", "POSSIBLE", "EARTHS", "GATHERED", "TRANSMITTED",
    # Additional common words to reach ~500
    "ABLE", "AREA", "AWAY", "BANK", "BASE", "BEAR", "BEAT", "BILL",
    "BLUE", "BOAT", "BONE", "BORN", "BURN", "BUSY", "CAMP", "CARD",
    "CARE", "CAST", "COAT", "COLD", "COPY", "COST", "CREW", "CROP",
    "DARE", "DEAL", "DENY", "DIET", "DISK", "DRAW", "DREW", "DRINK",
    "DRIVE", "DROVE", "DRUG", "DUST", "DUTY", "EARN", "EDGE", "ELSE",
    "FAIR", "FARM", "FAST", "FATE", "FILM", "FIRM", "FISH", "FLAG",
    "FLAT", "FLEW", "FLOW", "FOLD", "FOLK", "FOOL", "FUEL", "FUND",
    "GAIN", "GAME", "GATE", "GIFT", "GLAD", "GOAL", "GOES", "GOLD",
    "GRAB", "GRAY", "GREY", "GREW", "GRIN", "GRIP", "GUARD", "GUEST",
    "GUIDE", "GUILTY", "HANG", "HATE", "HEAL", "HEAT", "HERO", "HIDE",
    "HILL", "HIRE", "HOLE", "HOST", "HUGE", "HUNG", "HUNT", "HURT",
    "IRON", "ITEM", "JACK", "JAIL", "JANE", "JEAN", "JOIN", "JOKE",
    "JUDGE", "JUMP", "JURY", "KEEN", "KICK", "KILL", "KNEE", "KNOT",
    "LACK", "LAID", "LAKE", "LAMP", "LANE", "LEAN", "LEAP", "LEND",
    "LINK", "LOAD", "LOAN", "LOCK", "LONE", "LUNG", "MAIL", "MAIN",
    "MALE", "MASS", "MATE", "MEAL", "MERE", "MILE", "MILK", "MINE",
    "MODE", "MOOD", "MOON", "MINE", "MYTH", "NAIL", "NECK", "NODE",
    "NONE", "NOON", "NORM", "NOSE", "NOTE", "ODDS", "OKAY", "PACE",
    "PACK", "PAGE", "PAID", "PAIN", "PAIR", "PALE", "PALM", "PARK",
    "PASS", "PAST", "PATH", "PEAK", "PEER", "PICK", "PILE", "PINE",
    "PINK", "PIPE", "PLAN", "PLOT", "PLUG", "PLUS", "POEM", "POET",
    "POLE", "POLL", "POND", "POOL", "POOR", "POPE", "PORT", "POUR",
    "PRAY", "PULL", "PUMP", "PURE", "PUSH", "RACE", "RAIN", "RANK",
    "RARE", "RATE", "RELY", "RENT", "REST", "RICE", "RIDE", "RING",
    "RISE", "RISK", "ROAD", "ROCK", "RODE", "ROLE", "ROLL", "ROOF",
    "ROOT", "ROPE", "ROSE", "RUIN", "RULE", "RUSH", "SAFE", "SAIL",
    "SAKE", "SALE", "SALT", "SAND", "SANG", "SAVE", "SEAL", "SEAT",
    "SEED", "SEEK", "SELF", "SELL", "SHED", "SHIP", "SHOP", "SHOT",
    "SHUT", "SICK", "SIGN", "SILK", "SINK", "SITE", "SIZE", "SKIN",
    "SLIP", "SLOW", "SNAP", "SNOW", "SOFT", "SOIL", "SOLE", "SONG",
    "SOON", "SORT", "SOUL", "SPOT", "STAR", "STAY", "STEM", "STEP",
    "STIR", "SUIT", "SURE", "SWIM", "TAIL", "TALE", "TALL", "TANK",
    "TAPE", "TASK", "TEAM", "TEAR", "TERM", "TEST", "TEXT", "THIN",
    "TIED", "TILL", "TINY", "TIRE", "TONE", "TOOK", "TOOL", "TOPS",
    "TORE", "TOUR", "TOWN", "TRAP", "TREE", "TRIM", "TRIP", "TUBE",
    "TUNE", "TYPE", "UNIT", "VAST", "VIEW", "VOTE", "WAGE", "WAIT",
    "WAKE", "WALK", "WARN", "WASH", "WAVE", "WEAK", "WEAR", "WILD",
    "WINE", "WING", "WIRE", "WISE", "WISH", "WOOD", "WORE", "WRAP",
    "YARD", "YEAH", "ZERO", "ZONE",
}, key=lambda w: (-len(w), w))

# ---------------------------------------------------------------------------
# Trie for greedy longest-match word coverage
# ---------------------------------------------------------------------------

class TrieNode:
    __slots__ = ("children", "word")
    def __init__(self):
        self.children: dict[str, TrieNode] = {}
        self.word: str | None = None

def build_trie(words: list[str]) -> TrieNode:
    root = TrieNode()
    for w in words:
        node = root
        for ch in w:
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.word = w
    return root

def greedy_word_coverage(text: str, trie_root: TrieNode) -> tuple[float, list[str]]:
    """Greedy longest-match word coverage.
    Returns (fraction_covered, list_of_words_found).
    """
    n = len(text)
    if n == 0:
        return 0.0, []
    covered = [False] * n
    words_found = []
    i = 0
    while i < n:
        node = trie_root
        best_end = -1
        best_word = None
        j = i
        while j < n and text[j] in node.children:
            node = node.children[text[j]]
            j += 1
            if node.word is not None:
                best_end = j
                best_word = node.word
        if best_word is not None and len(best_word) >= 3:
            for k in range(i, best_end):
                covered[k] = True
            words_found.append(best_word)
            i = best_end
        else:
            i += 1
    coverage = sum(covered) / n
    return coverage, words_found


# ---------------------------------------------------------------------------
# Quagmire III Decryption
# ---------------------------------------------------------------------------

def decrypt_quagmire3(ciphertext: str, keyword: str, key_offset: int = 0,
                       tableau: list[str] | None = None) -> str:
    """Decrypt ciphertext with Quagmire III using KRYPTOS alphabet.
    
    keyword: the repeating key
    key_offset: start position within the keyword (0 = normal)
    """
    if tableau is None:
        tableau = build_quagmire_tableau()
    
    kw_len = len(keyword)
    result = []
    for i, c in enumerate(ciphertext):
        key_idx = (i + key_offset) % kw_len
        key_char = keyword[key_idx]
        # Find row index for key char in KRYPTOS_ALPHABET
        if key_char not in KRYPTOS_ALPHABET or c not in KRYPTOS_ALPHABET:
            result.append(c)
            continue
        row_idx = KRYPTOS_ALPHABET.index(key_char)
        shifted_row = tableau[row_idx]
        if c in shifted_row:
            p = shifted_row.index(c)
            result.append(KRYPTOS_ALPHABET[p])
        else:
            result.append(c)
    return "".join(result)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_anchor_match(plaintext: str, pos_offset: int = 0) -> tuple[int, int, dict]:
    """Score how many anchor characters match at expected positions.
    pos_offset: if we think the plaintext starts at K4 position pos_offset
                (i.e., the first pos_offset chars are preamble).
    Returns (chars_matched, total_anchor_chars, per_anchor_detail).
    """
    total = 0
    matched = 0
    detail = {}
    for name, start, end in ANCHORS:
        adj_start = start - pos_offset
        adj_end = end - pos_offset
        if adj_start < 0 or adj_end > len(plaintext):
            detail[name] = {"matched": 0, "total": end - start, "got": "OUT_OF_RANGE"}
            total += end - start
            continue
        segment = plaintext[adj_start:adj_end]
        m = sum(1 for a, b in zip(segment, name) if a == b)
        matched += m
        total += len(name)
        detail[name] = {"matched": m, "total": len(name), "expected": name, "got": segment}
    return matched, total, detail


def compute_score(plaintext: str, trie_root: TrieNode, pos_offset: int = 0) -> dict:
    """Compute a combined score for a candidate plaintext."""
    # Anchor matching
    anchor_matched, anchor_total, anchor_detail = score_anchor_match(plaintext, pos_offset)
    anchor_score = anchor_matched / max(anchor_total, 1)
    
    # Word coverage
    coverage, words = greedy_word_coverage(plaintext, trie_root)
    
    # Unique words of length >= 4
    long_words = [w for w in words if len(w) >= 4]
    unique_long = len(set(long_words))
    
    # Combined score: heavily weight anchors, plus word coverage
    # Anchor score 0-1 (weight 60), coverage 0-1 (weight 30), long word bonus (weight 10)
    combined = (anchor_score * 60.0 +
                coverage * 30.0 +
                min(unique_long / 10.0, 1.0) * 10.0)
    
    return {
        "combined": round(combined, 4),
        "anchor_score": round(anchor_score, 4),
        "anchor_matched": anchor_matched,
        "anchor_total": anchor_total,
        "anchor_detail": anchor_detail,
        "word_coverage": round(coverage, 4),
        "words_found": words,
        "unique_long_words": unique_long,
    }


# ---------------------------------------------------------------------------
# Main Search
# ---------------------------------------------------------------------------

def main():
    print(f"=" * 72)
    print(f"Strategy {STRATEGY_ID}: {STRATEGY_NAME}")
    print(f"=" * 72)
    print(f"K4 ciphertext ({len(K4)} chars): {K4}")
    print(f"KRYPTOS alphabet: {KRYPTOS_ALPHABET}")
    print(f"Keywords to test: {len(KEYWORDS)}")
    print(f"Dictionary words: {len(DICTIONARY)}")
    print()

    tableau = build_quagmire_tableau()
    trie_root = build_trie(DICTIONARY)
    
    # Position offsets to try (preamble before known plaintext)
    POS_OFFSETS = [0, 1, 2, 3]
    
    start_time = time.time()
    
    results = []
    total_tested = 0
    best_score = 0.0
    best_result = None
    
    for keyword in KEYWORDS:
        # Validate keyword chars are all in KRYPTOS_ALPHABET
        valid_kw = all(ch in KRYPTOS_ALPHABET for ch in keyword)
        if not valid_kw:
            print(f"  SKIP {keyword}: contains chars not in KRYPTOS alphabet")
            continue
        
        kw_len = len(keyword)
        
        for key_offset in range(kw_len):
            for pos_offset in POS_OFFSETS:
                plaintext = decrypt_quagmire3(K4, keyword, key_offset, tableau)
                score_info = compute_score(plaintext, trie_root, pos_offset)
                total_tested += 1
                
                combined = score_info["combined"]
                
                if combined > best_score:
                    best_score = combined
                    best_result = {
                        "keyword": keyword,
                        "key_offset": key_offset,
                        "pos_offset": pos_offset,
                        "plaintext": plaintext,
                        "score": score_info,
                    }
                    print(f"  NEW BEST: keyword={keyword} key_off={key_offset} "
                          f"pos_off={pos_offset} => score={combined:.4f} "
                          f"anchors={score_info['anchor_matched']}/{score_info['anchor_total']} "
                          f"coverage={score_info['word_coverage']:.3f}")
                    if score_info['anchor_matched'] >= 5:
                        print(f"    PLAINTEXT: {plaintext}")
                        print(f"    WORDS: {score_info['words_found'][:20]}")
                        print(f"    ANCHOR DETAIL: {score_info['anchor_detail']}")
                
                # Keep results with decent scores
                if combined >= 15.0:
                    results.append({
                        "keyword": keyword,
                        "key_offset": key_offset,
                        "pos_offset": pos_offset,
                        "plaintext": plaintext,
                        "score": score_info,
                    })
    
    elapsed = time.time() - start_time
    
    # Also try the standard build_score_breakdown for top candidates
    results.sort(key=lambda r: r["score"]["combined"], reverse=True)
    top_results = results[:50]
    
    # Add framework scoring for top results
    for r in top_results:
        try:
            breakdown = build_score_breakdown(r["plaintext"])
            r["framework_score"] = breakdown
        except Exception as e:
            r["framework_score"] = {"error": str(e)}
    
    # Print summary
    print()
    print(f"=" * 72)
    print(f"SEARCH COMPLETE")
    print(f"=" * 72)
    print(f"Total configurations tested: {total_tested}")
    print(f"Results with score >= 15: {len(results)}")
    print(f"Elapsed: {elapsed:.2f}s")
    print()
    
    if best_result:
        print(f"BEST RESULT:")
        print(f"  Keyword:    {best_result['keyword']}")
        print(f"  Key offset: {best_result['key_offset']}")
        print(f"  Pos offset: {best_result['pos_offset']}")
        print(f"  Plaintext:  {best_result['plaintext']}")
        print(f"  Score:      {best_result['score']['combined']:.4f}")
        print(f"  Anchors:    {best_result['score']['anchor_matched']}/{best_result['score']['anchor_total']}")
        print(f"  Coverage:   {best_result['score']['word_coverage']:.3f}")
        print(f"  Words:      {best_result['score']['words_found'][:30]}")
        anchor_d = best_result['score']['anchor_detail']
        for name in anchor_d:
            d = anchor_d[name]
            print(f"    {name}: expected={d.get('expected','?')} got={d.get('got','?')} "
                  f"matched={d['matched']}/{d['total']}")
    
    # Print top 20
    print()
    print(f"TOP 20 RESULTS:")
    print(f"-" * 72)
    for i, r in enumerate(top_results[:20]):
        s = r["score"]
        print(f"  {i+1:2d}. keyword={r['keyword']:15s} key_off={r['key_offset']:2d} "
              f"pos_off={r['pos_offset']} score={s['combined']:7.4f} "
              f"anch={s['anchor_matched']}/{s['anchor_total']} "
              f"cov={s['word_coverage']:.3f} "
              f"words={len(s['words_found'])}")
        if s['anchor_matched'] >= 5:
            print(f"      PT: {r['plaintext']}")
    
    # Check if any result has significant anchor matches
    print()
    print(f"ANCHOR ANALYSIS:")
    print(f"-" * 72)
    anchor_sorted = sorted(results, 
                           key=lambda r: r["score"]["anchor_matched"], reverse=True)
    for r in anchor_sorted[:10]:
        s = r["score"]
        print(f"  keyword={r['keyword']:15s} key_off={r['key_offset']:2d} "
              f"pos_off={r['pos_offset']} anchors={s['anchor_matched']}/{s['anchor_total']}")
        for name, detail in s["anchor_detail"].items():
            if detail["matched"] > 0:
                print(f"    {name}: {detail.get('got','?')} (matched {detail['matched']}/{detail['total']})")
    
    # Save results
    output = {
        "strategy_id": STRATEGY_ID,
        "strategy_name": STRATEGY_NAME,
        "k4_ciphertext": K4,
        "kryptos_alphabet": KRYPTOS_ALPHABET,
        "keywords_tested": KEYWORDS,
        "total_configurations": total_tested,
        "elapsed_seconds": round(elapsed, 2),
        "results_above_threshold": len(results),
        "best_result": best_result,
        "top_20": top_results[:20],
        "top_anchor_matches": [
            {
                "keyword": r["keyword"],
                "key_offset": r["key_offset"],
                "pos_offset": r["pos_offset"],
                "plaintext": r["plaintext"],
                "anchor_matched": r["score"]["anchor_matched"],
                "anchor_total": r["score"]["anchor_total"],
                "anchor_detail": r["score"]["anchor_detail"],
                "word_coverage": r["score"]["word_coverage"],
                "combined_score": r["score"]["combined"],
            }
            for r in anchor_sorted[:20]
        ],
    }
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)
    
    print()
    print(f"Results saved to: {OUTPUT_FILE}")
    print(f"Done.")


if __name__ == "__main__":
    main()
