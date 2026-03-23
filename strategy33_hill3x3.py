"""Strategy 33: Hill 3x3 Cipher + Transposition.

A 3x3 Hill cipher has 9 key parameters. With 24 known plaintext chars
= 8 aligned triples, we have enough to solve (3 triples = 9 equations)
and verify (5 remaining triples).

Also brute-force is infeasible (26^9 = 5.4 trillion), so we rely on
algebraic solving from known plaintext triples.
"""
from __future__ import annotations

import sys
import time
import json

sys.path.insert(0, ".")

from kryptos.constants import K4, ANCHOR_COMPONENT_CLUES, STANDARD_ALPHABET
from kryptos.common import build_score_breakdown
from kryptos.transposition import periodic_transposition_decrypt, keyword_permutation

ANCHORS: list[tuple[str, int]] = []
for _c, _d in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_c, int(_d["start_index"]) - 1))

KNOWN_PT: dict[int, str] = {}
for clue, start in ANCHORS:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

N = len(K4)

# Word coverage
_W = (
    "THE AND FOR ARE BUT NOT YOU ALL CAN HER WAS ONE OUR OUT DAY GET HAS "
    "HIM HIS HOW ITS LET MAY NEW NOW OLD SEE WAY WHO DID SAY SHE TOO USE "
    "THAT HAVE WITH THIS WILL YOUR FROM THEY BEEN CALL COME EACH FIND GIVE "
    "HIGH JUST KNOW LIKE LONG LOOK MAKE MANY MUCH MUST NAME OVER PART SUCH "
    "TAKE THAN THEM THEN TURN VERY WANT WELL WHAT WHEN WORK YEAR ALSO BACK "
    "BOTH CAME DONE DOWN EVEN FACT FOUR GAVE GONE GOOD HAND HELP HERE HOME "
    "INTO KEEP KIND LAST LEFT LIFE LINE MADE MEAN MORE MOST MOVE NEED NEXT "
    "ONCE ONLY OPEN PLAY SAID SAME SEEM SHOW SIDE SOME SURE TELL TIME UPON "
    "ABOUT AFTER AGAIN BEING COULD EVERY FIRST FOUND GREAT HOUSE LARGE "
    "LATER LEARN NEVER OFTEN ORDER OTHER PLACE POINT RIGHT SHALL SINCE "
    "SMALL SOUND STILL STUDY THEIR THERE THESE THING THINK THOSE THREE "
    "UNDER UNTIL WATER WHERE WHICH WHILE WORLD WOULD WRITE YOUNG ABOVE "
    "ALONG BEGIN CARRY CAUSE CHILD CLOSE COVER CROSS EARLY EARTH ENTER "
    "EAST NORTHEAST BERLIN CLOCK EGYPT TOMB CHAMBER PASSAGE CORRIDOR "
    "TUNNEL SECRET HIDDEN BURIED LOCATION LATITUDE LONGITUDE DEGREES "
    "MINUTES SECONDS POSITION SHADOW LIGHT ILLUSION BETWEEN SUBTLE "
    "INFORMATION GATHERED TRANSMITTED UNDERGROUND LANGLEY SLOWLY "
    "DESPERATELY REMAINS DEBRIS TREMBLING HANDS BREACH CANDLE FLICKER "
    "EMERGED MIST ANYTHING CARTER HOWARD DISCOVERY ANCIENT CIPHER "
    "MYSTERY CLUE ANSWER SOLUTION TREASURE MUSEUM PYRAMID TEMPLE DESERT "
    "VALLEY PALACE GARDEN FOUNTAIN STATUE COLUMN WALL GATE DOOR WINDOW "
    "FLOOR ROOM HALL TOWER SQUARE WORLD TIME KRYPTOS PALIMPSEST ABSCISSA "
    "SANBORN MESSAGE ACROSS ACTION ALWAYS AMOUNT ANSWER APPEAR AROUND "
    "ATTACK BECOME BEFORE BEHIND BETTER BEYOND BORDER BOTTOM BRANCH "
    "BRIDGE BROKEN CANNOT CAREER CHANGE CHARGE CHOICE CHURCH COMMON "
    "CORNER COUPLE COURSE DANGER DECADE DECIDE DEGREE DEMAND DESIGN "
    "DETAIL DIRECT DIVIDE DOCTOR DURING EFFECT EFFORT EMERGE ENERGY "
    "ENGINE ENOUGH ENTIRE ESCAPE EVENTS EXPECT EXPERT EXTEND EXTENT "
    "FACING FACTOR FAMILY FATHER FIGURE FINGER FINISH FOLLOW FORCED "
    "FOREST FORGET FORMER FOURTH FRIEND FUTURE GARDEN GATHER GLOBAL "
    "GROUND GROWTH HAPPEN HEALTH HIGHLY HONEST IMPACT IMPORT INCOME "
    "INDEED INFORM INSIDE ISLAND ITSELF LAUNCH LEADER LENGTH LETTER "
    "LIKELY LIVING MARKED MARKET MASTER MATTER MEMBER MEMORY METHOD "
    "MIDDLE MINUTE MODERN MOMENT MOTION MUSEUM NATION NATURE NEARBY "
    "NEARLY NEEDED NORMAL NOTICE NUMBER OBJECT OFFICE OPTION ORIGIN "
    "OUTPUT PARENT PEOPLE PERIOD PERSON PLACED PLANET PLEASE POLICY "
    "PUBLIC RATHER READER REASON RECENT RECORD REDUCE REFORM REGARD "
    "REGION REMAIN REMOTE REMOVE REPEAT REPORT RESIST RESULT RETURN "
    "REVEAL REVIEW SAFETY SAMPLE SCHOOL SEARCH SECRET SELECT SENIOR "
    "SERIES SETTLE SIGNAL SILENT SIMPLE SINGLE SOCIAL SOURCE SPEECH "
    "SPIRIT SPREAD SPRING SQUARE STABLE STRAIN STREAM STREET STRESS "
    "STRIKE STRING STRONG SUPPLY SURELY SURVEY SWITCH SYMBOL SYSTEM "
    "TARGET TEMPLE THIRTY THREAT TOWARD TRAVEL TWENTY UNIQUE UNLESS "
    "UPDATE USEFUL VALLEY VISION VOLUME WEALTH WEIGHT WINTER WITHIN "
    "WONDER WORTHY WRITER"
)

class _T:
    __slots__ = ("c", "e", "w")
    def __init__(self):
        self.c: dict[str, _T] = {}
        self.e = False
        self.w = ""

def _bt(ws):
    r = _T()
    for w in ws:
        n = r
        for ch in w:
            if ch not in n.c: n.c[ch] = _T()
            n = n.c[ch]
        n.e = True; n.w = w
    return r

def wcov(text, trie):
    n = len(text); cov = [False]*n; ws = []; p = 0
    while p < n:
        nd = trie; bw = ""; be = p
        for j in range(p, n):
            if text[j] not in nd.c: break
            nd = nd.c[text[j]]
            if nd.e and len(nd.w) >= 3: bw = nd.w; be = j+1
        if bw:
            ws.append(bw)
            for k in range(p, be): cov[k] = True
            p = be
        else: p += 1
    cc = sum(cov)
    return {"cov": cc/n if n else 0, "ws": ws}

def ahits(text):
    return sum(sum(1 for a, b in zip(text[s:s+len(c)], c) if a == b)
               for c, s in ANCHORS if s+len(c) <= len(text))

# ---------------------------------------------------------------------------
# Modular arithmetic
# ---------------------------------------------------------------------------
def mod_inv(a, m=26):
    for x in range(m):
        if (a * x) % m == 1: return x
    return None

def mat3_det(M):
    """Determinant of 3x3 matrix mod 26."""
    return (M[0][0]*(M[1][1]*M[2][2]-M[1][2]*M[2][1])
           -M[0][1]*(M[1][0]*M[2][2]-M[1][2]*M[2][0])
           +M[0][2]*(M[1][0]*M[2][1]-M[1][1]*M[2][0])) % 26

def mat3_adj(M):
    """Adjugate (cofactor transpose) of 3x3 matrix mod 26."""
    adj = [[0]*3 for _ in range(3)]
    adj[0][0] = (M[1][1]*M[2][2] - M[1][2]*M[2][1]) % 26
    adj[0][1] = (-(M[0][1]*M[2][2] - M[0][2]*M[2][1])) % 26
    adj[0][2] = (M[0][1]*M[1][2] - M[0][2]*M[1][1]) % 26
    adj[1][0] = (-(M[1][0]*M[2][2] - M[1][2]*M[2][0])) % 26
    adj[1][1] = (M[0][0]*M[2][2] - M[0][2]*M[2][0]) % 26
    adj[1][2] = (-(M[0][0]*M[1][2] - M[0][2]*M[1][0])) % 26
    adj[2][0] = (M[1][0]*M[2][1] - M[1][1]*M[2][0]) % 26
    adj[2][1] = (-(M[0][0]*M[2][1] - M[0][1]*M[2][0])) % 26
    adj[2][2] = (M[0][0]*M[1][1] - M[0][1]*M[1][0]) % 26
    return adj

def mat3_inv(M):
    """Inverse of 3x3 matrix mod 26, or None."""
    det = mat3_det(M)
    di = mod_inv(det, 26)
    if di is None: return None
    adj = mat3_adj(M)
    return [[(adj[r][c] * di) % 26 for c in range(3)] for r in range(3)]

def mat3_mul(A, B):
    """Multiply two 3x3 matrices mod 26."""
    return [[(sum(A[r][k]*B[k][c] for k in range(3))) % 26 for c in range(3)] for r in range(3)]

def hill3_decrypt(text, K_inv):
    result = []
    for i in range(0, len(text)-2, 3):
        v = [ord(text[i+j])-65 for j in range(3)]
        for row in range(3):
            p = sum(K_inv[row][c]*v[c] for c in range(3)) % 26
            result.append(STANDARD_ALPHABET[p])
    rem = len(text) % 3
    if rem: result.extend(text[-rem:])
    return "".join(result)

def get_hill3_triples(inter):
    """Get aligned triples of (c0,c1,c2, p0,p1,p2) from known plaintext."""
    triples = []
    sorted_pos = sorted(KNOWN_PT.keys())
    for idx in range(len(sorted_pos)-2):
        p1, p2, p3 = sorted_pos[idx], sorted_pos[idx+1], sorted_pos[idx+2]
        if p2 == p1+1 and p3 == p1+2 and p1 % 3 == 0:
            c = [ord(inter[p1+j])-65 for j in range(3)]
            pt = [ord(KNOWN_PT[p1+j])-65 for j in range(3)]
            triples.append((*c, *pt))
    return triples

def solve_hill3(triples):
    """Solve for K_inv from known (cipher, plain) triples.
    K_inv * C = P, so K_inv = P * C^(-1).
    Need 3 triples for a 3x3 system.
    """
    if len(triples) < 3:
        return None

    n = len(triples)
    # Try all combinations of 3 triples
    for i in range(n):
        for j in range(i+1, n):
            for k in range(j+1, n):
                t = [triples[i], triples[j], triples[k]]
                # C matrix: columns are cipher triples
                C = [[t[col][row] for col in range(3)] for row in range(3)]
                # P matrix: columns are plain triples
                P = [[t[col][row+3] for col in range(3)] for row in range(3)]

                C_inv = mat3_inv(C)
                if C_inv is None:
                    continue

                K_inv = mat3_mul(P, C_inv)

                # Verify against ALL triples
                ok = True
                for tr in triples:
                    cv = [tr[0], tr[1], tr[2]]
                    pv = [tr[3], tr[4], tr[5]]
                    for row in range(3):
                        dp = sum(K_inv[row][c]*cv[c] for c in range(3)) % 26
                        if dp != pv[row]:
                            ok = False
                            break
                    if not ok: break

                if ok:
                    return K_inv
    return None


def main():
    t0 = time.perf_counter()
    raw = set()
    for w in _W.split():
        w = w.strip().upper()
        if len(w) >= 3 and all(c in STANDARD_ALPHABET for c in w):
            raw.add(w)
    trie = _bt(sorted(raw))
    print(f"Dictionary: {len(raw)} words")

    all_results = []
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "LONGITUDE",
        "BERLIN", "CLOCK", "SANBORN", "SHADOW", "EGYPT", "CARTER",
        "ILLUSION", "LANGLEY", "MESSAGE", "NORTHEAST", "TOMB", "HIDDEN",
        "POSITION", "DEGREES", "TREASURE", "SECRET", "ANCIENT",
    ]

    # ===================================================================
    # PHASE 1: Direct Hill 3x3 on K4
    # ===================================================================
    print(f"\n{'='*72}")
    print("PHASE 1: Direct Hill 3x3 on K4")
    print("="*72)

    triples = get_hill3_triples(K4)
    print(f"  Found {len(triples)} aligned known-plaintext triples")
    K_inv = solve_hill3(triples)
    if K_inv:
        text = hill3_decrypt(K4, K_inv)
        cov = wcov(text, trie)
        ah = ahits(text)
        print(f"  SOLVED! K_inv={K_inv}")
        print(f"  Text: {text}")
        print(f"  Coverage: {cov['cov']:.1%}, Anchors: {ah}")
        all_results.append({
            "text": text, "keyword": "none", "width": 0,
            "permutation": [], "coverage": cov["cov"],
            "words": cov["ws"], "anchor_hits": ah,
            "project_score": build_score_breakdown(text)["total"],
            "phase": "direct_hill3", "key_matrix": K_inv,
        })
    else:
        print("  No consistent 3x3 Hill key for raw K4.")

    # ===================================================================
    # PHASE 2: Hill 3x3 after transposition
    # ===================================================================
    print(f"\n{'='*72}")
    print("PHASE 2: Hill 3x3 after transposition")
    print("="*72)

    checked = 0
    solved = 0
    for kw in keywords:
        for width in range(2, 16):
            perm = keyword_permutation(kw, width)
            for fm, rm in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(K4, width, perm, fill_mode=fm, read_mode=rm)
                checked += 1

                triples = get_hill3_triples(inter)
                if len(triples) < 3:
                    continue

                K_inv = solve_hill3(triples)
                if K_inv is None:
                    continue

                solved += 1
                text = hill3_decrypt(inter, K_inv)
                cov = wcov(text, trie)
                ah = ahits(text)
                bd = build_score_breakdown(text)
                all_results.append({
                    "text": text, "keyword": kw, "width": width,
                    "permutation": list(perm),
                    "coverage": cov["cov"], "words": cov["ws"],
                    "anchor_hits": ah,
                    "project_score": bd["total"],
                    "phase": "trans_hill3", "key_matrix": K_inv,
                })
                if cov["cov"] > 0.20:
                    print(f"  *** HIT: kw={kw} w={width} cov={cov['cov']:.1%} ah={ah}")

    elapsed = time.perf_counter() - t0
    print(f"\n  Checked {checked}, solved {solved}, {len(all_results)} results, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 3: Exhaustive permutations widths 3,6,9 (multiples of 3)
    # ===================================================================
    print(f"\n{'='*72}")
    print("PHASE 3: Exhaustive permutations (widths 3,6)")
    print("="*72)

    from itertools import permutations as iter_perms
    for width in [3, 6]:
        p3_checked = 0
        p3_solved = 0
        for perm in iter_perms(range(width)):
            for fm, rm in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(K4, width, perm, fill_mode=fm, read_mode=rm)
                p3_checked += 1

                triples = get_hill3_triples(inter)
                if len(triples) < 3:
                    continue

                K_inv = solve_hill3(triples)
                if K_inv is None:
                    continue

                p3_solved += 1
                text = hill3_decrypt(inter, K_inv)
                cov = wcov(text, trie)
                ah = ahits(text)
                bd = build_score_breakdown(text)
                all_results.append({
                    "text": text, "keyword": f"perm{perm}", "width": width,
                    "permutation": list(perm),
                    "coverage": cov["cov"], "words": cov["ws"],
                    "anchor_hits": ah,
                    "project_score": bd["total"],
                    "phase": "exhaustive_hill3", "key_matrix": K_inv,
                })
                if cov["cov"] > 0.20:
                    print(f"  *** HIT: w={width} perm={perm} cov={cov['cov']:.1%} ah={ah}")

        elapsed = time.perf_counter() - t0
        print(f"  width={width}: checked {p3_checked}, solved {p3_solved}, {elapsed:.1f}s")

    # ===================================================================
    # RESULTS
    # ===================================================================
    all_results.sort(key=lambda x: (-x["coverage"], -x["anchor_hits"]))
    elapsed = time.perf_counter() - t0

    print(f"\n{'='*72}")
    print(f"FINAL RESULTS ({elapsed:.1f}s, {len(all_results)} candidates)")
    print("="*72)

    if all_results:
        for i, r in enumerate(all_results[:15]):
            print(f"#{i+1:>2} cov={r['coverage']:.1%} ah={r['anchor_hits']:>2} "
                  f"proj={r['project_score']:>3} w={r['width']:>2} "
                  f"kw={r['keyword'][:12]:<12} K={r['key_matrix']}")
            print(f"     words: {' '.join(r['words'][:6])}")
            print(f"     text:  {r['text'][:65]}...")
    else:
        print("No Hill 3x3 candidates found.")

    output = {
        "strategy": "hill_3x3",
        "total_candidates": len(all_results),
        "elapsed_seconds": elapsed,
        "top_results": all_results[:50],
    }
    with open("runs/hill_3x3.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/hill_3x3.json")


if __name__ == "__main__":
    main()
