"""Strategy 31: Hill Cipher + Transposition.

A Hill cipher uses matrix multiplication mod 26 on groups of n letters.
For a 2x2 Hill cipher, pairs (a,b) of plaintext are multiplied by a 2x2
key matrix K to produce ciphertext pairs. This is NON-periodic and produces
near-random IC — matching K4's IC of 0.036.

With 24 known plaintext characters, we have 12 known plaintext PAIRS.
Each pair gives us 2 linear equations in 4 unknowns (the key matrix entries).
So 2 known pairs (4 equations, 4 unknowns) can solve for K exactly.
The remaining 10 pairs serve as verification.

For a 3x3 Hill cipher, we need 3 known triples (9 equations, 9 unknowns).
With 24 known chars = 8 triples, we can solve and verify.

Phases:
1. Direct Hill 2x2 on K4 (no transposition)
2. Hill 2x2 after each transposition hypothesis
3. Hill 3x3 on K4 and after transposition
4. Score all consistent results with dictionary word coverage
"""
from __future__ import annotations

import sys
import time
import json
from itertools import permutations as iter_perms

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, ANCHOR_COMPONENT_CLUES, STANDARD_ALPHABET,
)
from kryptos.common import build_score_breakdown
from kryptos.transposition import (
    periodic_transposition_decrypt, keyword_permutation,
    existing_cells, fill_order, read_order,
)

# ---------------------------------------------------------------------------
# Known plaintext (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _c, _d in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_c, int(_d["start_index"]) - 1))

KNOWN_PT: dict[int, str] = {}
for clue, start in ANCHORS:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

N = len(K4)

# ---------------------------------------------------------------------------
# Word trie (compact)
# ---------------------------------------------------------------------------
_WORDS = (
    "THE AND FOR ARE BUT NOT YOU ALL CAN HER WAS ONE OUR OUT DAY GET HAS "
    "HIM HIS HOW ITS LET MAY NEW NOW OLD SEE WAY WHO DID SAY SHE TOO USE "
    "THAT HAVE WITH THIS WILL YOUR FROM THEY BEEN CALL COME EACH FIND GIVE "
    "HIGH JUST KNOW LIKE LONG LOOK MAKE MANY MUCH MUST NAME OVER PART SUCH "
    "TAKE THAN THEM THEN TURN VERY WANT WELL WHAT WHEN WORK YEAR ALSO BACK "
    "BOTH CAME DONE DOWN EVEN FACT FOUR GAVE GONE GOOD HAND HELP HERE HOME "
    "INTO KEEP KIND LAST LEFT LIFE LINE LIST LIVE MADE MEAN MORE MOST MOVE "
    "NEED NEXT ONCE ONLY OPEN PLAY SAID SAME SEEM SHOW SIDE SOME SURE TELL "
    "TIME UPON USED WENT WERE WORD ABOUT AFTER AGAIN BEING COULD EVERY "
    "FIRST FOUND GREAT GROUP HOUSE LARGE LATER LEARN NEVER OFTEN ORDER "
    "OTHER PLACE POINT RIGHT SHALL SINCE SMALL SOUND STILL STOOD STUDY "
    "THEIR THERE THESE THING THINK THOSE THREE UNDER UNTIL WATER WHERE "
    "WHICH WHILE WORLD WOULD WRITE YOUNG ABOVE ALONG BEGIN CARRY CAUSE "
    "CHILD CLOSE COVER CROSS EARLY EARTH ENTER EQUAL EXACT EXIST FINAL "
    "FORCE GIVEN GREEN HEAVY HENCE HORSE HUMAN INNER ISSUE KNOWN LAYER "
    "LEVEL LOCAL MAJOR MATCH MEANT METAL MIGHT MONEY MONTH MOVED MUSIC "
    "NIGHT NORTH NOVEL OCCUR OUTER OWNER PAPER PARTY PEACE PLAIN POWER "
    "PRESS PRICE PRIME PROOF PROVE QUICK QUITE RAISE RANGE REACH READY "
    "REFER RIVER ROUND ROYAL SCENE SENSE SERVE SEVEN SHAPE SHARE SHORT "
    "SHOWN SIGHT SLEEP SOLID SOLVE SOUTH SPACE SPOKE STAGE STAND START "
    "STATE STONE STORE STORY STYLE SWEET TABLE TAKEN TEETH TENTH THEME "
    "THICK THIRD THROW TIGHT TITLE TODAY TOTAL TOUCH TOWER TRACK TRADE "
    "TRAIN TREAT TREND TRIAL TRIED TRUCK TRULY TRUST TRUTH TWICE UNION "
    "UNITE UPPER UPSET URBAN USUAL VALID VALUE VISIT VITAL VOICE WASTE "
    "WATCH WHEEL WHITE WHOLE WHOSE WOMEN WORSE WORST WORTH WROTE YOUTH "
    "EAST NORTHEAST BERLIN CLOCK EGYPT TOMB CHAMBER PASSAGE CORRIDOR "
    "TUNNEL SECRET HIDDEN BURIED LOCATION LATITUDE LONGITUDE DEGREES "
    "MINUTES SECONDS POSITION SHADOW LIGHT ILLUSION BETWEEN SUBTLE "
    "MAGNETIC FIELD INFORMATION GATHERED TRANSMITTED UNDERGROUND UNKNOWN "
    "LANGLEY SLOWLY DESPERATELY REMAINS DEBRIS TREMBLING HANDS BREACH "
    "CANDLE FLICKER EMERGED MIST ANYTHING CARTER HOWARD DISCOVERY "
    "ANCIENT CIPHER DECODE ALPHABET CODE PUZZLE MYSTERY CLUE ANSWER "
    "SOLUTION TREASURE VAULT ARTIFACT MUSEUM STONE TABLET PYRAMID TEMPLE "
    "DESERT RIVER VALLEY PALACE GARDEN FOUNTAIN STATUE COLUMN WALL GATE "
    "DOOR WINDOW FLOOR CEILING STEP STAIR ROOM HALL TOWER SQUARE WORLD "
    "TIME INSCRIPTION KRYPTOS PALIMPSEST ABSCISSA SANBORN MESSAGE "
    "ACROSS ACTION ALWAYS AMOUNT ANSWER APPEAR AROUND ATTACK BECOME "
    "BEFORE BEHIND BETTER BEYOND BORDER BOTTOM BRANCH BRIDGE BROKEN "
    "CANNOT CAREER CAUGHT CAUSED CENTER CHANGE CHARGE CHOICE CHURCH "
    "COMMON CORNER COUPLE COURSE DANGER DECADE DECIDE DEGREE DEMAND "
    "DESERT DESIGN DETAIL DIRECT DIVIDE DOCTOR DRIVEN DURING EASILY "
    "EFFECT EFFORT EMERGE ENABLE ENERGY ENGINE ENOUGH ENTIRE ESCAPE "
    "EVENTS EXCEPT EXPECT EXPERT EXTEND EXTENT FACING FACTOR FAIRLY "
    "FAMILY FATHER FIGURE FINGER FINISH FOLLOW FORCED FOREST FORGET "
    "FORMER FOURTH FRIEND FUTURE GARDEN GATHER GLOBAL GOLDEN GROUND "
    "GROWTH HAPPEN HEALTH HEAVEN HIGHLY HONEST IMPACT IMPORT INCOME "
    "INDEED INFORM INJURY INSIDE INTENT ISLAND ITSELF LAUNCH LAWYER "
    "LEADER LENGTH LETTER LIGHTS LIKELY LIVING MARKED MARKET MASTER "
    "MATTER MEMBER MEMORY METHOD MIDDLE MINING MINUTE MIRROR MODERN "
    "MOMENT MOTION MURDER MUSEUM NATION NATURE NEARBY NEARLY NEEDED "
    "NORMAL NOTICE NUMBER OBJECT OBTAIN OFFICE OPTION ORIGIN OUTPUT "
    "PARENT PASSED PEOPLE PERIOD PERMIT PERSON PLACED PLANET PLAYER "
    "PLEASE POCKET POLICY PUBLIC RAISED RATHER READER REASON RECENT "
    "RECORD REDUCE REFORM REGARD REGION REJECT RELATE RELIEF REMAIN "
    "REMOTE REMOVE REPEAT REPORT RESIST RESULT RETAIN RETIRE RETURN "
    "REVEAL REVIEW RISING SAFETY SAMPLE SCHEME SCHOOL SEARCH SECRET "
    "SELECT SENIOR SERIES SETTLE SEVERE SIGNAL SILENT SILVER SIMPLE "
    "SINGLE SMOOTH SOCIAL SOURCE SPEECH SPIRIT SPREAD SPRING STABLE "
    "STRAIN STRAND STREAM STREET STRESS STRICT STRIKE STRING STRONG "
    "SUPPLY SURELY SURVEY SWITCH SYMBOL SYSTEM TARGET TAUGHT TEMPLE "
    "THIRTY THREAT TOWARD TRAVEL TWENTY UNIQUE UNLESS UPDATE USEFUL "
    "VALLEY VICTIM VISION VOLUME WEALTH WEEKLY WEIGHT WINTER WISDOM "
    "WITHIN WONDER WORKER WORTHY WRITER "
    "ABILITY ABSENCE ACCOUNT ACHIEVE ACQUIRE ADDRESS ADVANCE ALREADY "
    "ANCIENT ANOTHER ARTICLE ATTEMPT AVERAGE BALANCE BARRIER BEARING "
    "BECAUSE BELIEVE BENEATH BILLION BROUGHT CABINET CAPABLE CAPITAL "
    "CAPTAIN CAREFUL CARRIED CENTRAL CENTURY CERTAIN CHAPTER CHARGED "
    "CITIZEN CLAIMED CLASSIC CLIMATE CLOSEST CLOTHES COLLECT COLLEGE "
    "COMMAND COMMENT COMPANY COMPARE COMPLEX CONCERN CONDUCT CONFIRM "
    "CONNECT CONSIST CONTACT CONTAIN CONTENT CONTEXT CONTROL CONVERT "
    "CORRECT COUNCIL COUNTER COUNTRY COURAGE COVERED CREATED CULTURE "
    "CURRENT DEALING DECLARE DECLINE DEFENCE DELIVER DEPOSIT DERIVED "
    "DESPITE DEVELOP DIGITAL DISEASE DISPLAY DISTANT DIVIDED DRAWING "
    "DRIVING DROPPED EASTERN ECONOMY EDITION ELDERLY ELEMENT EMOTION "
    "ENABLED ENDLESS ENGAGED ENHANCE ENJOYED EPISODE ESSENCE EXAMINE "
    "EXAMPLE EXCITED EXECUTE EXHIBIT EXPENSE EXPLAIN EXPLOIT EXPLORE "
    "EXPOSED EXPRESS EXTREME FAILING FAILURE FASHION FEATURE FEELING "
    "FICTION FIGHTER FINALLY FINANCE FINDING FOREIGN FOREVER FORMULA "
    "FORTUNE FORWARD FOUNDED FREEDOM FURTHER GENETIC GENUINE GETTING "
    "GRANTED GROWING HABITAT HEADING HERSELF HIGHWAY HIMSELF HISTORY "
    "HOLDING HOLIDAY HOUSING HOWEVER HUNDRED HUNTING HUSBAND ILLEGAL "
    "IMAGINE INITIAL INQUIRY INSTEAD INVOLVE KILLING KINGDOM KITCHEN "
    "KNOWING LANDING LARGELY LEADING LEARNED LIBERAL LIBRARY LIMITED "
    "LINKING LOOKING MACHINE MANAGER MARRIED MASSIVE MEASURE MEDICAL "
    "MEETING MENTION MILLION MINERAL MINIMUM MISSING MISSION MIXTURE "
    "MONITOR MONTHLY MORNING MYSTERY NATURAL NEITHER NETWORK NOTHING "
    "NUCLEAR OBVIOUS OFFICER OPINION OUTCOME OVERALL PAINFUL PARTIAL "
    "PARTNER PASSAGE PASSING PATIENT PATTERN PAYMENT PENALTY PENSION "
    "PERCENT PERFECT PERFORM PERHAPS PICTURE POINTED POPULAR PORTION "
    "POVERTY PRESENT PREVENT PRIMARY PRIVATE PROBLEM PROCEED PROCESS "
    "PRODUCE PRODUCT PROFILE PROJECT PROMISE PROMOTE PROPOSE PROTECT "
    "PROTEIN PROTEST PROVIDE PUBLISH PURPOSE QUALIFY QUARTER QUICKLY "
    "RADICAL RAILWAY READING REALITY RECEIVE RECOVER REFLECT REGULAR "
    "RELATED RELEASE REMAINS REMOVAL REMOVED REPLACE REQUEST REQUIRE "
    "RESERVE RESOLVE RESPECT RESPOND RESTORE REVENUE REVERSE ROUTINE "
    "RUNNING SATISFY SCIENCE SECTION SEGMENT SERIOUS SERVICE SESSION "
    "SETTING SEVENTH SEVERAL SHELTER SILENCE SIMILAR SITTING SOCIETY "
    "SOLDIER SOMEONE SPEAKER SPECIAL SPONSOR STARTED STATION STORAGE "
    "STRANGE STRETCH SUCCESS SUGGEST SUPPORT SUPPOSE SURFACE SURVIVE "
    "SUSPECT TEACHER TENSION THOUGHT THROUGH TONIGHT TOTALLY TOWARDS "
    "TRAFFIC TROUBLE TURNING TYPICAL UNIFORM UNKNOWN UNUSUAL VARIETY "
    "VEHICLE VERSION VILLAGE VIOLENT VIRTUAL VISIBLE WARNING WEBSITE "
    "WELCOME WESTERN WHETHER WILLING WITHOUT WRITING"
)

class _T:
    __slots__ = ("c", "e", "w")
    def __init__(self):
        self.c: dict[str, _T] = {}
        self.e = False
        self.w = ""

def _bt(words):
    r = _T()
    for w in words:
        n = r
        for ch in w:
            if ch not in n.c: n.c[ch] = _T()
            n = n.c[ch]
        n.e = True; n.w = w
    return r

def wcov(text, trie, ml=3):
    n = len(text); cov = [False]*n; ws = []; p = 0
    while p < n:
        nd = trie; bw = ""; be = p
        for j in range(p, n):
            if text[j] not in nd.c: break
            nd = nd.c[text[j]]
            if nd.e and len(nd.w) >= ml: bw = nd.w; be = j+1
        if bw:
            ws.append(bw)
            for k in range(p, be): cov[k] = True
            p = be
        else: p += 1
    cc = sum(cov)
    return {"cov": cc/n if n else 0, "cc": cc, "ws": ws, "nw": len(ws),
            "lw": max(ws, key=len, default="")}

def ahits(text):
    return sum(sum(1 for a, b in zip(text[s:s+len(c)], c) if a == b)
               for c, s in ANCHORS if s+len(c) <= len(text))

# ---------------------------------------------------------------------------
# Modular arithmetic helpers
# ---------------------------------------------------------------------------
def mod_inv(a: int, m: int = 26) -> int | None:
    """Modular inverse of a mod m, or None if not invertible."""
    for x in range(m):
        if (a * x) % m == 1:
            return x
    return None

def mat2_inv(K: list[list[int]]) -> list[list[int]] | None:
    """Inverse of 2x2 matrix mod 26."""
    det = (K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26
    di = mod_inv(det, 26)
    if di is None:
        return None
    return [
        [(K[1][1] * di) % 26, ((-K[0][1]) * di) % 26],
        [((-K[1][0]) * di) % 26, (K[0][0] * di) % 26],
    ]

def hill2_decrypt(text: str, K_inv: list[list[int]]) -> str:
    """Decrypt text with 2x2 Hill cipher using inverse key matrix."""
    result = []
    for i in range(0, len(text) - 1, 2):
        a = ord(text[i]) - 65
        b = ord(text[i+1]) - 65
        p0 = (K_inv[0][0] * a + K_inv[0][1] * b) % 26
        p1 = (K_inv[1][0] * a + K_inv[1][1] * b) % 26
        result.append(STANDARD_ALPHABET[p0])
        result.append(STANDARD_ALPHABET[p1])
    if len(text) % 2 == 1:
        result.append(text[-1])  # Odd char through unchanged
    return "".join(result)

def hill3_decrypt(text: str, K_inv: list[list[int]]) -> str:
    """Decrypt with 3x3 Hill cipher."""
    result = []
    for i in range(0, len(text) - 2, 3):
        v = [ord(text[i+j]) - 65 for j in range(3)]
        for row in range(3):
            p = sum(K_inv[row][col] * v[col] for col in range(3)) % 26
            result.append(STANDARD_ALPHABET[p])
    rem = len(text) % 3
    if rem:
        result.extend(text[-rem:])
    return "".join(result)

def solve_hill2(pairs: list[tuple[int, int, int, int]]) -> list[list[int]] | None:
    """Given known (c0, c1, p0, p1) pairs, solve for the 2x2 key matrix.

    Hill encryption: [c0, c1] = K * [p0, p1] mod 26
    So K_inv * [c0, c1] = [p0, p1]
    We solve for K_inv directly from known (cipher, plain) pairs.

    Need 2 linearly independent pairs to solve uniquely.
    """
    if len(pairs) < 2:
        return None

    # Try all pairs of 2 equations
    for i in range(len(pairs)):
        for j in range(i+1, len(pairs)):
            c0a, c1a, p0a, p1a = pairs[i]
            c0b, c1b, p0b, p1b = pairs[j]

            # System: K_inv * [[c0a, c0b], [c1a, c1b]] = [[p0a, p0b], [p1a, p1b]]
            # C_mat = [[c0a, c0b], [c1a, c1b]]
            # P_mat = [[p0a, p0b], [p1a, p1b]]
            # K_inv = P_mat * C_mat^(-1)

            det_C = (c0a * c1b - c0b * c1a) % 26
            di = mod_inv(det_C, 26)
            if di is None:
                continue

            C_inv = [
                [(c1b * di) % 26, ((-c0b) * di) % 26],
                [((-c1a) * di) % 26, (c0a * di) % 26],
            ]

            # K_inv = P_mat * C_inv
            K_inv = [[0, 0], [0, 0]]
            P_mat = [[p0a, p0b], [p1a, p1b]]
            for r in range(2):
                for c in range(2):
                    K_inv[r][c] = (P_mat[r][0] * C_inv[0][c] + P_mat[r][1] * C_inv[1][c]) % 26

            # Verify against ALL pairs
            all_match = True
            for c0, c1, p0, p1 in pairs:
                dp0 = (K_inv[0][0] * c0 + K_inv[0][1] * c1) % 26
                dp1 = (K_inv[1][0] * c0 + K_inv[1][1] * c1) % 26
                if dp0 != p0 or dp1 != p1:
                    all_match = False
                    break

            if all_match:
                return K_inv

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    t0 = time.perf_counter()

    raw = set()
    for w in _WORDS.split():
        w = w.strip().upper()
        if len(w) >= 3 and all(c in STANDARD_ALPHABET for c in w):
            raw.add(w)
    trie = _bt(sorted(raw))
    print(f"Dictionary: {len(raw)} words")

    all_results: list[dict] = []
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "LONGITUDE",
        "BERLIN", "CLOCK", "SANBORN", "SHADOW", "EGYPT", "CARTER",
        "ILLUSION", "LANGLEY", "MESSAGE", "NORTHEAST", "TOMB", "LUCENT",
        "HIDDEN", "POSITION", "DEGREES",
    ]

    # ===================================================================
    # Build known plaintext pairs for Hill 2x2
    # ===================================================================
    # We need pairs of (cipher[i], cipher[i+1], plain[i], plain[i+1])
    # where both positions are known.

    def get_hill2_pairs(inter: str) -> list[tuple[int, int, int, int]]:
        """Get consecutive known-plaintext pairs from intermediate text."""
        pairs = []
        sorted_pos = sorted(KNOWN_PT.keys())
        for idx in range(len(sorted_pos) - 1):
            p1, p2 = sorted_pos[idx], sorted_pos[idx + 1]
            if p2 == p1 + 1 and p1 % 2 == 0:
                # Consecutive and aligned to pair boundary
                c0 = ord(inter[p1]) - 65
                c1 = ord(inter[p2]) - 65
                pt0 = ord(KNOWN_PT[p1]) - 65
                pt1 = ord(KNOWN_PT[p2]) - 65
                pairs.append((c0, c1, pt0, pt1))
        return pairs

    # ===================================================================
    # PHASE 1: Direct Hill 2x2 on K4
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 1: Direct Hill 2x2 on K4 (no transposition)")
    print("=" * 72)

    pairs = get_hill2_pairs(K4)
    print(f"  Found {len(pairs)} aligned known-plaintext pairs")

    K_inv = solve_hill2(pairs)
    if K_inv:
        text = hill2_decrypt(K4, K_inv)
        cov = wcov(text, trie)
        ah = ahits(text)
        print(f"  SOLVED! K_inv={K_inv}")
        print(f"  Text: {text}")
        print(f"  Coverage: {cov['cov']:.1%}, Words: {cov['ws']}")
        all_results.append({
            "text": text, "keyword": "none", "width": 0,
            "permutation": [], "fill_mode": "none", "read_mode": "none",
            "coverage": cov["cov"], "words": cov["ws"],
            "longest": cov["lw"], "anchor_hits": ah,
            "project_score": build_score_breakdown(text)["total"],
            "phase": "direct_hill2", "key_matrix": K_inv,
        })
    else:
        print("  No consistent 2x2 Hill key found for raw K4.")

    # ===================================================================
    # PHASE 2: Hill 2x2 after transposition
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 2: Hill 2x2 after transposition")
    print("=" * 72)

    phase2_checked = 0
    phase2_solved = 0

    for kw in keywords:
        for width in range(2, 16):
            perm = keyword_permutation(kw, width)
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)
                phase2_checked += 1

                pairs = get_hill2_pairs(inter)
                if len(pairs) < 2:
                    continue

                K_inv = solve_hill2(pairs)
                if K_inv is None:
                    continue

                phase2_solved += 1
                text = hill2_decrypt(inter, K_inv)
                cov = wcov(text, trie)
                ah = ahits(text)
                bd = build_score_breakdown(text)

                all_results.append({
                    "text": text, "keyword": kw, "width": width,
                    "permutation": list(perm),
                    "fill_mode": fill_mode, "read_mode": read_mode,
                    "coverage": cov["cov"], "words": cov["ws"],
                    "longest": cov["lw"], "anchor_hits": ah,
                    "project_score": bd["total"],
                    "phase": "trans_hill2", "key_matrix": K_inv,
                })
                if cov["cov"] > 0.25:
                    print(f"  *** HIT: kw={kw} w={width} cov={cov['cov']:.1%} "
                          f"ah={ah} K_inv={K_inv}")

    elapsed = time.perf_counter() - t0
    print(f"\n  Checked {phase2_checked}, solved {phase2_solved}, "
          f"{len(all_results)} results, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 3: Brute-force all 2x2 Hill keys (only 26^4 = 456,976)
    # with and without LATITUDE transposition
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 3: Brute-force all 2x2 Hill keys")
    print("=" * 72)

    for label, inter in [("raw_K4", K4),
                         ("LATITUDE_trans", periodic_transposition_decrypt(
                             K4, 6, keyword_permutation("LATITUDE", 6),
                             fill_mode="row", read_mode="column"))]:
        print(f"\n  Testing {label}...")
        best_cov = 0.0
        best_text = ""
        best_K = None
        checked = 0

        for a in range(26):
            for b in range(26):
                for c in range(26):
                    for d in range(26):
                        # Check determinant is invertible
                        det = (a * d - b * c) % 26
                        if mod_inv(det, 26) is None:
                            continue
                        checked += 1
                        K_inv = [[a, b], [c, d]]
                        text = hill2_decrypt(inter, K_inv)
                        ah = ahits(text)
                        if ah >= 16:  # At least most anchors match
                            cov_r = wcov(text, trie)
                            if cov_r["cov"] > best_cov:
                                best_cov = cov_r["cov"]
                                best_text = text
                                best_K = [list(row) for row in K_inv]

                            if ah == 24:
                                bd = build_score_breakdown(text)
                                all_results.append({
                                    "text": text, "keyword": label, "width": 0,
                                    "permutation": [],
                                    "fill_mode": "none", "read_mode": "none",
                                    "coverage": cov_r["cov"], "words": cov_r["ws"],
                                    "longest": cov_r["lw"], "anchor_hits": ah,
                                    "project_score": bd["total"],
                                    "phase": f"brute_hill2_{label}",
                                    "key_matrix": [list(row) for row in K_inv],
                                })

        elapsed = time.perf_counter() - t0
        print(f"    Checked {checked} invertible matrices, "
              f"best coverage={best_cov:.1%}, best ah={ahits(best_text) if best_text else 0}")
        if best_text and best_cov > 0.10:
            print(f"    Best text: {best_text[:60]}...")
            cov_r = wcov(best_text, trie)
            print(f"    Words: {cov_r['ws'][:8]}")
            print(f"    K_inv: {best_K}")

    # ===================================================================
    # RESULTS
    # ===================================================================
    all_results.sort(key=lambda x: (-x["coverage"], -x["anchor_hits"]))

    elapsed = time.perf_counter() - t0
    print(f"\n{'=' * 72}")
    print(f"FINAL RESULTS ({elapsed:.1f}s, {len(all_results)} candidates)")
    print("=" * 72)

    for i, r in enumerate(all_results[:20]):
        print(f"#{i+1:>2} cov={r['coverage']:.1%} ah={r['anchor_hits']:>2} "
              f"proj={r['project_score']:>3} w={r['width']:>2} "
              f"kw={r['keyword'][:12]:<12} K={r['key_matrix']}")
        print(f"     words: {' '.join(r['words'][:8])}")
        print(f"     text:  {r['text'][:70]}...")

    if all_results:
        print(f"\n{'=' * 72}")
        print("DETAILED TOP 5")
        print("=" * 72)
        for i, r in enumerate(all_results[:5]):
            print(f"\n--- #{i+1} (phase: {r['phase']}) ---")
            print(f"Key matrix (inverse): {r['key_matrix']}")
            print(f"Trans: kw={r['keyword']} width={r['width']}")
            print(f"Text: {r['text']}")
            print(f"Coverage: {r['coverage']:.1%}, Words: {r['words']}")
            for clue, start in ANCHORS:
                end = start + len(clue)
                if end <= len(r["text"]):
                    seg = r["text"][start:end]
                    hits = sum(1 for a, b in zip(seg, clue) if a == b)
                    status = "MATCH" if seg == clue else f"{hits}/{len(clue)}"
                    print(f"  {clue:>13} at {start}: \"{seg}\" [{status}]")
    else:
        print("\nNo Hill cipher candidates found.")

    # Save
    output = {
        "strategy": "hill_cipher",
        "total_candidates": len(all_results),
        "elapsed_seconds": elapsed,
        "top_results": [
            {k: v for k, v in r.items()}
            for r in all_results[:50]
        ],
    }
    with open("runs/hill_cipher.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/hill_cipher.json")


if __name__ == "__main__":
    main()
