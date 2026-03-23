"""Strategy 30: Simple Substitution + Transposition.

The paradigm shift: instead of periodic Vigenere, try a MONOALPHABETIC
(simple) substitution after transposition. With 24 known plaintext
characters, a simple substitution gives us 24 known letter mappings.
If those 24 mappings are self-consistent (no letter maps to two different
targets), we've potentially fixed 24 of 26 substitution slots, leaving
only 2 unknown. That's testable exhaustively in milliseconds.

This is fundamentally different from the constraint-first Vigenere approach
because monoalphabetic substitution has only 26 parameters (one per letter)
vs Vigenere's 26^period parameters. The constraint is MUCH tighter.

Phases:
1. For each transposition hypothesis, check if monoalphabetic substitution
   is self-consistent at all 24 known positions
2. For consistent configs, fill the 0-2 unknown mappings exhaustively
3. Score the FULL plaintext with dictionary word coverage
4. Also try: no transposition (pure substitution), and encryption-order
   variants (substitution first, then transposition)
"""
from __future__ import annotations

import sys
import time
import json
import random
from itertools import permutations as iter_perms, product

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, ANCHOR_COMPONENT_CLUES, STANDARD_ALPHABET, KRYPTOS_ALPHABET,
)
from kryptos.common import build_score_breakdown, normalize_letters
from kryptos.transposition import (
    periodic_transposition_decrypt, periodic_transposition_encrypt,
    keyword_permutation, identity_permutation,
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
# Embedded word trie (compact)
# ---------------------------------------------------------------------------
_WORDS = (
    "THE AND FOR ARE BUT NOT YOU ALL CAN HER WAS ONE OUR OUT DAY GET HAS "
    "HIM HIS HOW ITS LET MAY NEW NOW OLD SEE WAY WHO DID SAY SHE TOO USE "
    "THAT HAVE WITH THIS WILL YOUR FROM THEY BEEN CALL COME EACH FIND GIVE "
    "HIGH JUST KNOW LIKE LONG LOOK MAKE MANY MUCH MUST NAME OVER PART SUCH "
    "TAKE THAN THEM THEN TURN VERY WANT WELL WHAT WHEN WORK YEAR ALSO BACK "
    "BOTH CAME DONE DOWN EVEN FACT FOUR GAVE GONE GOOD HAND HELP HERE HOME "
    "INTO KEEP KIND LAST LEFT LIFE LINE LIST LIVE LONG MADE MANY MEAN MORE "
    "MOST MOVE NEED NEXT ONCE ONLY OPEN OWN PLAY SAID SAME SEEM SHOW SIDE "
    "SOME SURE TELL TIME UPON USED WENT WERE WORD ABOUT AFTER AGAIN BEING "
    "BELOW COULD EVERY FIRST FOUND GREAT GROUP HOUSE LARGE LATER LEARN "
    "NEVER OFTEN ORDER OTHER PLACE PLANT POINT RIGHT SHALL SINCE SMALL "
    "SOUND SPELL STILL STOOD STUDY THEIR THERE THESE THING THINK THOSE "
    "THREE UNDER UNTIL WATER WHERE WHICH WHILE WORLD WOULD WRITE YOUNG "
    "ABOVE ALONG BEGIN CARRY CAUSE CHILD CLOSE COVER CROSS EARLY EARTH "
    "EIGHT ENDED ENTER EQUAL EXACT EXIST EXTRA FINAL FORCE GIVEN GREEN "
    "HEAVY HENCE HORSE HUMAN INNER ISSUE KNOWN LAYER LEVEL LOCAL MAJOR "
    "MATCH MEANT METAL MIGHT MONEY MONTH MOVED MUSIC NIGHT NORTH NOTED "
    "NOVEL OCCUR OUTER OWNER PAPER PARTY PEACE PLAIN POWER PRESS PRICE "
    "PRIME PROOF PROVE QUICK QUITE RADIO RAISE RANGE RAPID REACH READY "
    "REFER RIGHT RIVER ROUND ROYAL SCENE SENSE SERVE SEVEN SHAPE SHARE "
    "SHORT SHOWN SIGHT SLEEP SMITH SOLID SOLVE SOUTH SPACE SPOKE STAGE "
    "STAND START STATE STONE STORE STORY STUCK STYLE SUGAR SWEET TABLE "
    "TAKEN TEETH TENTH THEME THICK THIRD THROW TIGHT TITLE TODAY TOTAL "
    "TOUCH TOWER TRACK TRADE TRAIN TREAT TREND TRIAL TRIED TRUCK TRULY "
    "TRUST TRUTH TWICE UNION UNITE UNTIL UPPER UPSET URBAN USAGE USUAL "
    "VALID VALUE VISIT VITAL VOICE WASTE WATCH WATER WHEEL WHITE WHOLE "
    "WHOSE WOMEN WORSE WORST WORTH WROTE YOUTH "
    "ACROSS ACTION ADVISE AFFECT ALMOST ALWAYS AMOUNT ANIMAL ANSWER "
    "APPEAR AROUND ARRIVE ATTACK BECOME BEFORE BEHIND BETTER BEYOND "
    "BORDER BOTTOM BRANCH BREATH BRIDGE BROKEN CANNOT CAREER CAUGHT "
    "CAUSED CENTER CHANGE CHARGE CHOICE CHURCH CIRCLE CITIES CLOSED "
    "COFFEE COMING COMMON CORNER COUPLE COURSE DANGER DEBATE DECADE "
    "DECIDE DEGREE DEMAND DESERT DESIGN DETAIL DIRECT DIVIDE DOCTOR "
    "DRIVEN DURING EASILY EATING EFFECT EFFORT EIGHTH EMERGE EMPIRE "
    "ENABLE ENERGY ENGINE ENOUGH ENTIRE ESCAPE ESTATE EVENTS EVOLVE "
    "EXCEPT EXPECT EXPERT EXTEND EXTENT FACING FACTOR FAIRLY FALLEN "
    "FAMILY FATHER FELLOW FIGURE FINGER FINISH FLIGHT FOLLOW FORCED "
    "FOREST FORGET FORMAL FORMER FOURTH FRIEND FUTURE GARDEN GATHER "
    "GENTLE GLOBAL GOLDEN GOTTEN GROUND GROWTH HAPPEN HARDLY HEALTH "
    "HEAVEN HIGHLY HONEST HORROR IMPACT IMPORT INCOME INDEED INFORM "
    "INJURY INSIDE INTENT ISLAND ITSELF JOINED JUNIOR KILLED LAUNCH "
    "LAWYER LEADER LENGTH LETTER LIGHTS LIKELY LIVING LOSING MARKED "
    "MARKET MASTER MATTER MEDIUM MEMBER MEMORY MENTAL METHOD MIDDLE "
    "MILLER MINING MINUTE MIRROR MODERN MOMENT MOTION MURDER MUSEUM "
    "MUTUAL NAMELY NARROW NATION NATIVE NATURE NEARBY NEARLY NEEDED "
    "NORMAL NOTICE NUMBER OBJECT OBTAIN OFFICE OPPOSE OPTION ORIGIN "
    "OUTPUT PARENT PARTLY PASSED PATENT PEOPLE PERIOD PERMIT PERSON "
    "PLACED PLANET PLAYER PLEASE POCKET POLICY PREFER PUBLIC PURSUE "
    "RAISED RARELY RATHER READER REASON RECENT RECORD REDUCE REFORM "
    "REGARD REGIME REGION REJECT RELATE RELIEF REMAIN REMOTE REMOVE "
    "REPEAT REPORT RESIST RESULT RETAIN RETIRE RETURN REVEAL REVIEW "
    "RISING RULING SAFETY SALARY SAMPLE SCHEME SCHOOL SEARCH SECRET "
    "SECURE SELECT SENATE SENIOR SERIES SETTLE SEVERE SIGNAL SILENT "
    "SILVER SIMPLE SIMPLY SINGLE SLIGHT SMOOTH SOCIAL SOLELY SOURCE "
    "SPEECH SPIRIT SPREAD SPRING SQUARE STABLE STRAIN STRAND STREAM "
    "STREET STRESS STRICT STRIKE STRING STRONG STRUCK SUPPLY SURELY "
    "SURVEY SWITCH SYMBOL SYSTEM TAKING TARGET TAUGHT TEMPLE TENANT "
    "THIRTY THREAT THROWN TOWARD TRAVEL TREATY TRIBAL TWENTY UNIQUE "
    "UNLESS UPDATE USEFUL VALLEY VARIED VICTIM VISION VOLUME WALKER "
    "WEALTH WEEKLY WEIGHT WINTER WISDOM WITHIN WONDER WORKER WORTHY "
    "WRITER YELLOW "
    "ABILITY ABSENCE ACADEMY ACCOUNT ACHIEVE ACQUIRE ADDRESS ADVANCE "
    "ALREADY ANCIENT ANOTHER APPLIED ARRANGE ARTICLE ATTEMPT AVERAGE "
    "BALANCE BARRIER BEARING BECAUSE BEDROOM BELIEVE BENEATH BESIDES "
    "BILLION BROUGHT CABINET CAPABLE CAPITAL CAPTAIN CAREFUL CARRIED "
    "CENTRAL CENTURY CERTAIN CHAPTER CHARGED CHARITY CHECKED CHICKEN "
    "CHRONIC CITIZEN CLAIMED CLASSIC CLIMATE CLOSEST CLOTHES COLLECT "
    "COLLEGE COMMAND COMMENT COMPANY COMPARE COMPLEX CONCERN CONDUCT "
    "CONFIRM CONNECT CONSIST CONTACT CONTAIN CONTENT CONTEXT CONTROL "
    "CONVERT CORRECT COUNCIL COUNTER COUNTRY COURAGE COVERED CREATED "
    "CRICKET CULTURE CURRENT DEALING DECLARE DECLINE DEFENCE DELIVER "
    "DENSITY DEPOSIT DERIVED DESPITE DEVELOP DEVOTED DIGITAL DISEASE "
    "DISPLAY DISTANT DIVIDED DRAWING DRESSED DRIVING DROPPED EASTERN "
    "ECONOMY EDITION ELDERLY ELEMENT EMOTION ENABLED ENDLESS ENGAGED "
    "ENHANCE ENJOYED ENQUIRY EPISODE ESSENCE EXAMINE EXAMPLE EXCITED "
    "EXCLUDE EXECUTE EXHIBIT EXPENSE EXPLAIN EXPLOIT EXPLORE EXPOSED "
    "EXPRESS EXTREME FAILING FAILURE FASHION FEATURE FEELING FICTION "
    "FIGHTER FINALLY FINANCE FINDING FOREIGN FOREVER FORMULA FORTUNE "
    "FORWARD FOUNDED FREEDOM FURTHER GENETIC GENUINE GETTING GRANTED "
    "GROWING HABITAT HANGING HEADING HERSELF HIGHWAY HIMSELF HISTORY "
    "HOLDING HOLIDAY HOUSING HOWEVER HUNDRED HUNTING HUSBAND ILLEGAL "
    "IMAGINE INITIAL INQUIRY INSTEAD INVOLVE KILLING KINGDOM KITCHEN "
    "KNOWING LANDING LARGELY LEADING LEARNED LENDING LIBERAL LIBRARY "
    "LICENCE LIMITED LINKING LISTING LOCALLY LOOKING MACHINE MANAGER "
    "MARRIED MASSIVE MEASURE MEDICAL MEETING MENTION MILITIA MILLION "
    "MINERAL MINIMUM MISSING MISSION MIXTURE MONITOR MONTHLY MORNING "
    "MYSTERY NATURAL NEITHER NETWORK NOTHING NUCLEAR OBVIOUS OFFICER "
    "OPINION ORGANIC OUTCOME OVERALL PAINFUL PARKING PARTIAL PARTNER "
    "PASSAGE PASSING PATIENT PATTERN PAYMENT PENALTY PENSION PERCENT "
    "PERFECT PERFORM PERHAPS PICTURE PLASTIC POINTED POPULAR PORTION "
    "POVERTY PRESENT PREVENT PRIMARY PRINTER PRIVATE PROBLEM PROCEED "
    "PROCESS PRODUCE PRODUCT PROFILE PROJECT PROMISE PROMOTE PROPOSE "
    "PROTECT PROTEIN PROTEST PROVIDE PUBLISH PURPOSE PUTTING QUALIFY "
    "QUARTER QUICKLY RADICAL RAILWAY READING REALITY RECEIVE RECOVER "
    "REFLECT REGULAR RELATED RELEASE REMAINS REMOVAL REMOVED REPLACE "
    "REQUEST REQUIRE RESERVE RESOLVE RESPECT RESPOND RESTORE REVENUE "
    "REVERSE ROLLING ROUTINE RUNNING SATISFY SCIENCE SECTION SEGMENT "
    "SERIOUS SERVICE SESSION SETTING SEVENTH SEVERAL SHELTER SILENCE "
    "SIMILAR SITTING SOCIETY SOLDIER SOMEONE SOMEHOW SPEAKER SPECIAL "
    "SPONSOR STADIUM STARTED STATION STORAGE STRANGE STRETCH SUCCESS "
    "SUGGEST SUPPORT SUPPOSE SURFACE SURVIVE SUSPECT TEACHER TENSION "
    "THEATRE THERAPY THEREBY THOUGHT THROUGH TONIGHT TOTALLY TOURISM "
    "TOWARDS TRAFFIC TROUBLE TURNING TYPICAL UNIFORM UNKNOWN UNUSUAL "
    "VARIETY VEHICLE VERSION VETERAN VILLAGE VIOLENT VIRTUAL VISIBLE "
    "WARNING WEBSITE WELCOME WESTERN WHETHER WILLING WITHOUT WRITING "
    # Kryptos-specific
    "EAST NORTHEAST BERLIN CLOCK EGYPT TOMB CHAMBER PASSAGE CORRIDOR "
    "TUNNEL SECRET HIDDEN BURIED LOCATION COORDINATES LATITUDE LONGITUDE "
    "DEGREES MINUTES SECONDS POSITION SHADOW LIGHT ILLUSION BETWEEN "
    "SUBTLE MAGNETIC FIELD INFORMATION GATHERED TRANSMITTED UNDERGROUND "
    "LANGLEY SLOWLY DESPERATELY REMAINS DEBRIS TREMBLING HANDS BREACH "
    "CANDLE FLICKER EMERGED MIST ANYTHING CARTER HOWARD WONDERFUL "
    "DISCOVERY EXCAVATION ARCHAEOLOGY ANCIENT CIPHER DECODE ENCRYPT "
    "DECRYPT ALPHABET CODE PUZZLE MYSTERY CLUE ANSWER SOLUTION "
    "TREASURE VAULT ARTIFACT MUSEUM STONE TABLET PYRAMID TEMPLE "
    "DESERT RIVER VALLEY PHARAOH PALACE GARDEN FOUNTAIN STATUE COLUMN "
    "WALL GATE DOOR WINDOW FLOOR CEILING STEP STAIR ROOM HALL TOWER "
    "CLOCK SQUARE WORLD TIME INSCRIPTION KRYPTOS PALIMPSEST ABSCISSA "
    "SANBORN SCHEIDT INVISIBLE MESSAGE DELIVER IQLUSION "
    "ABSOLUTE ACCEPTED ACCIDENT ACCURATE ACHIEVED ACTUALLY ADEQUATE "
    "ADVANCED AFFECTED ALLIANCE ALTHOUGH ANALYSIS ANNOUNCE ANYTHING "
    "ANYWHERE APPARENT APPROACH APPROVAL ARGUMENT ASSEMBLY ASSUMING "
    "ATTACHED ATTEMPTS AUDIENCE AUTONOMY BALANCED BASEBALL BATHROOM "
    "BECOMING BELIEVED BIRTHDAY BOUNDARY BREAKING BRINGING BUILDING "
    "BUSINESS CALENDAR CAMPAIGN CAPACITY CAPTURED CARRYING CASUALTY "
    "CATEGORY CEREMONY CHAIRMAN CHAMPION CHANGING CHEMICAL CHILDREN "
    "CHOOSING CIVILIAN CLEARING CLIMBING CLINICAL CLOTHING COACHING "
    "COLLAPSE COMBINED COMEBACK COMMERCE COMPARED COMPLETE COMPOSED "
    "COMPUTER CONCLUDE CONCRETE CONFLICT CONGRESS CONSIDER CONSTANT "
    "CONSUMER CONTAINS CONTINUE CONTRAST CONVINCE CORRIDOR COVERAGE "
    "CREATIVE CRIMINAL CRITICAL CROSSING CULTURAL CURRENCY CUSTOMER "
    "DAUGHTER DEADLINE DECEMBER DECISION DECLARED DECREASE DEFEATED "
    "DEFINING DEFINITE DELIVERY DEMANDED DESIGNER DETAILED DIABETES "
    "DIALOGUE DIRECTED DIRECTOR DISABLED DISCOVER DISCRETE DISORDER "
    "DISPATCH DISTINCT DISTRICT DOCTRINE DOCUMENT DOMESTIC DOMINANT "
    "DONATION DRAMATIC DRINKING DROPPING DURATION ECONOMIC EDUCATED "
    "ELECTION ELEVATED EMERGING EMISSION EMPHASIS EMPLOYED EMPLOYEE "
    "EMPLOYER ENCLOSED ENCODING ENORMOUS ENTIRELY ENTITLED ENTRANCE "
    "ENVELOPE EQUALITY EQUIPPED ESTIMATE EVALUATE EVIDENCE EVERYDAY "
    "EVERYONE EXCHANGE EXCITING EXCLUDED EXERCISE EXISTING EXPANDED "
    "EXPECTED EXPLICIT EXPLORED EXPOSURE EXTENDED EXTERNAL FACILITY "
    "FAMILIAR FAVORITE FEATURED FEEDBACK FESTIVAL FIGHTING FILENAME "
    "FINALIST FINISHED FLOATING FOLLOWED FOOTBALL FORECAST FORMERLY "
    "FOUNDING FOURTEEN FRACTION FRAGMENT FREQUENT FRONTIER FUNCTION "
    "GENERATE GOVERNOR GRADUATE GRAPHICS GRATEFUL GREATEST GUARDIAN "
    "GUIDANCE HANDLING HAPPENED HARDWARE HERITAGE HIGHLAND HISTORIC "
    "HOMELAND HOMELESS HONESTLY HOSPITAL IDENTITY IDEOLOGY IGNORANT "
    "IMAGINED IMPERIAL IMPLICIT IMPORTED IMPOSING IMPROVED INCIDENT "
    "INCLUDED INCREASE INDICATE INDIRECT INDUSTRY INFORMAL INFORMED "
    "INHERENT INNOCENT INSPIRED INSTANCE INTEGRAL INTENDED INTERACT "
    "INTEREST INTERNAL INVASION INVENTOR INVESTED INVESTOR INVOLVED "
    "ISOLATED JUDGMENT JUNCTION KEYBOARD LANDMARK LANGUAGE LAUNCHED "
    "LEARNING LIFETIME LITERARY LOCATION MAGAZINE MAINTAIN MAJORITY "
    "MANAGING MANIFEST MARGINAL MARRIAGE MATERIAL MEASURED MECHANIC "
    "MEDIEVAL MEMORIAL MERCHANT MIDNIGHT MILITARY MINISTER MINORITY "
    "MODERATE MOLECULE MOMENTUM MONOPOLY MOREOVER MORTGAGE MOVEMENT "
    "MULTIPLE MULTIPLY MUTATION NATIONAL NEGATIVE NINETEEN NORMALLY "
    "NORTHERN NOTEBOOK NOVEMBER NUMEROUS OBSTACLE OCCASION OCCUPIED "
    "OCCURRED OFFERING OFFICIAL OFFSHORE OPPONENT OPPOSITE ORDINARY "
    "ORGANISM ORGANIZE ORIGINAL ORTHODOX OUTBREAK OVERCOME OVERLOOK "
    "OVERVIEW PAINTING PARALLEL PARENTAL PARTICLE PASSPORT PATIENCE "
    "PEACEFUL PECULIAR PERCEIVE PERSONAL PETITION PHYSICAL PLANNING "
    "PLATFORM PLEASANT PLEASURE POINTING POLICIES POLITICS POSSIBLE "
    "POSSIBLY POWERFUL PRACTICE PRECIOUS PREGNANT PRESENCE PRESERVE "
    "PRESSING PRESSURE PRESUMED PREVIOUS PRINCESS PRINTING PRIORITY "
    "PRISONER PROBABLY PRODUCER PROFOUND PROGRESS PROMISED PROMPTLY "
    "PROPERLY PROPERTY PROPOSAL PROPOSED PROSPECT PROTOCOL PROVINCE "
    "PROVIDED PROVIDER PUBLICLY PURCHASE PURSUING QUANTITY QUESTION "
    "REACTION RECEIVED RECENTLY RECOVERY REDUCING REFERRAL REFERRED "
    "REGIONAL REGISTER REGULATE RELATION RELATIVE RELEASED RELEVANT "
    "RELIABLE RELIGION REMEMBER RENOWNED REPEATED REPLACED REPORTED "
    "REPORTER REPUBLIC REQUIRED RESEARCH RESIDENT RESIGNED RESOLVED "
    "RESOURCE RESPONSE RESTORED RESULTED RETAINED RETIRING RETRIEVE "
    "RETURNED REVEALED REVERSAL REVISION RHETORIC RIGOROUS ROMANTIC "
    "SCENARIO SCHEDULE SCRUTINY SEASONAL SECONDLY SECURITY SELECTED "
    "SEMESTER SEQUENCE SETTLING SHOOTING SHOPPING SHORTAGE SHOULDER "
    "SHUTDOWN SIDEWALK SLIGHTLY SMUGGLED SNAPSHOT SOFTWARE SOMEBODY "
    "SOMETIME SOUTHERN SPEAKING SPECIFIC SPECTRUM SPENDING SPORTING "
    "STANDARD STANDING STICKING STIMULUS STOPPING STRAIGHT STRANGER "
    "STRATEGY STRENGTH STRIKING STRONGLY STRUGGLE STUNNING SUBURBAN "
    "SUDDENLY SUFFERED SUITABLE SUPERIOR SUPPLIED SUPPLIER SUPPOSED "
    "SURGICAL SURPRISE SURVIVAL SURVIVED SURVIVOR SUSPENSE SYMBOLIC "
    "SYMPATHY SYNDROME TEACHING TEAMMATE TERMINAL TERRIFIC THEOLOGY "
    "THIRTEEN THOROUGH THOUSAND THROWING TOGETHER TOMORROW TOUCHING "
    "TRACKING TRILLION TROPICAL TROUBLED ULTIMATE UMBRELLA UNCOMMON "
    "UNDERWAY UNIVERSE UNLAWFUL UNLIKELY UNSTABLE UPRISING VALIDATE "
    "VALUABLE VARIABLE VELOCITY VERTICAL VICINITY VIOLENCE VOLATILE "
    "WEAKNESS WARRANTY WATCHDOG WHATEVER WHENEVER WHEREVER WILDLIFE "
    "WIRELESS WITHDRAW WORKSHOP YOURSELF"
)

class _Trie:
    __slots__ = ("ch", "end", "word")
    def __init__(self):
        self.ch: dict[str, _Trie] = {}
        self.end = False
        self.word = ""

def _build_trie(words):
    root = _Trie()
    for w in words:
        n = root
        for c in w:
            if c not in n.ch:
                n.ch[c] = _Trie()
            n = n.ch[c]
        n.end = True
        n.word = w
    return root

def word_coverage(text, trie, min_len=3):
    n = len(text)
    covered = [False] * n
    words = []
    pos = 0
    while pos < n:
        node = trie
        best_w = ""
        best_end = pos
        for j in range(pos, n):
            if text[j] not in node.ch:
                break
            node = node.ch[text[j]]
            if node.end and len(node.word) >= min_len:
                best_w = node.word
                best_end = j + 1
        if best_w:
            words.append((best_w, pos))
            for k in range(pos, best_end):
                covered[k] = True
            pos = best_end
        else:
            pos += 1
    cc = sum(covered)
    return {
        "coverage": cc / n if n else 0.0,
        "covered_chars": cc,
        "words": [w for w, _ in words],
        "num_words": len(words),
        "longest": max((w for w, _ in words), key=len, default=""),
    }


def anchor_hits(text):
    return sum(
        sum(1 for a, b in zip(text[s:s+len(c)], c) if a == b)
        for c, s in ANCHORS if s + len(c) <= len(text))


# ---------------------------------------------------------------------------
# Core: check monoalphabetic consistency after transposition
# ---------------------------------------------------------------------------
def check_mono_consistency(inter: str) -> dict | None:
    """Given intermediate text (after transposition inverse), check if a
    simple substitution mapping is consistent with all 24 known plaintext chars.

    Returns the partial mapping {cipher_char -> plain_char} or None if
    contradictory (one cipher letter maps to two different plain letters).
    """
    mapping: dict[str, str] = {}  # inter_char -> plain_char
    reverse: dict[str, str] = {}  # plain_char -> inter_char (for injectivity)

    for pos, plain_ch in KNOWN_PT.items():
        if pos >= len(inter):
            return None
        inter_ch = inter[pos]

        if inter_ch in mapping:
            if mapping[inter_ch] != plain_ch:
                return None  # Contradiction!
        else:
            mapping[inter_ch] = plain_ch

        if plain_ch in reverse:
            if reverse[plain_ch] != inter_ch:
                return None  # Not injective — two cipher chars map to same plain
        else:
            reverse[plain_ch] = inter_ch

    # Count how many of 26 letters are determined
    unmapped_cipher = [c for c in STANDARD_ALPHABET if c not in mapping]
    unmapped_plain = [c for c in STANDARD_ALPHABET if c not in reverse]

    return {
        "mapping": mapping,
        "reverse": reverse,
        "mapped_count": len(mapping),
        "unmapped_cipher": unmapped_cipher,
        "unmapped_plain": unmapped_plain,
    }


def apply_substitution(inter: str, mapping: dict[str, str]) -> str:
    """Apply substitution mapping. Unmapped chars become '?'."""
    return "".join(mapping.get(c, "?") for c in inter)


def apply_full_substitution(inter: str, mapping: dict[str, str],
                             unmapped_cipher: list[str],
                             unmapped_plain: list[str],
                             assignment: tuple[int, ...]) -> str:
    """Apply substitution with specific assignment for unmapped chars."""
    full = dict(mapping)
    for i, ci in enumerate(unmapped_cipher):
        full[ci] = unmapped_plain[assignment[i]]
    return "".join(full.get(c, "?") for c in inter)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    t0 = time.perf_counter()

    # Build word trie
    raw = set()
    for w in _WORDS.split():
        w = w.strip().upper()
        if len(w) >= 3 and all(c in STANDARD_ALPHABET for c in w):
            raw.add(w)
    trie = _build_trie(sorted(raw))
    print(f"Dictionary: {len(raw)} words")

    all_results: list[dict] = []

    # ===================================================================
    # PHASE 0: Pure monoalphabetic (no transposition)
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 0: Pure monoalphabetic substitution (no transposition)")
    print("=" * 72)

    result = check_mono_consistency(K4)
    if result:
        print(f"  Consistent! {result['mapped_count']} letters determined")
        print(f"  Mapping: {result['mapping']}")
        print(f"  Unmapped cipher: {result['unmapped_cipher']}")
        print(f"  Unmapped plain: {result['unmapped_plain']}")
        partial = apply_substitution(K4, result['mapping'])
        print(f"  Partial decrypt: {partial}")
    else:
        print("  INCONSISTENT — pure monoalphabetic substitution on raw K4 is impossible.")
        print("  (Expected: known plaintext positions reference the ciphertext directly,")
        print("   and some ciphertext letter maps to two different plaintext letters.)")

    # ===================================================================
    # PHASE 1: Transposition + monoalphabetic
    # For each transposition, check consistency
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 1: Columnar transposition + monoalphabetic substitution")
    print("=" * 72)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "LONGITUDE",
        "BERLIN", "CLOCK", "SANBORN", "SHADOW", "EGYPT", "CARTER",
        "ILLUSION", "LANGLEY", "MESSAGE", "NORTHEAST", "TOMB", "LUCENT",
        "HIDDEN", "POSITION", "DEGREES", "MINUTES", "SECONDS", "COMPASS",
        "TEMPLE", "DESERT", "TREASURE", "ANCIENT", "DISCOVERY", "SECRET",
    ]

    phase1_checked = 0
    phase1_consistent = 0

    for kw in keywords:
        for width in range(2, 21):
            perm = keyword_permutation(kw, width)
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)
                phase1_checked += 1

                result = check_mono_consistency(inter)
                if result is None:
                    continue

                phase1_consistent += 1
                n_unc = len(result["unmapped_cipher"])

                if n_unc == 0:
                    # Fully determined!
                    text = apply_substitution(inter, result["mapping"])
                    cov = word_coverage(text, trie)
                    ah = anchor_hits(text)
                    bd = build_score_breakdown(text)
                    all_results.append({
                        "text": text,
                        "keyword": kw, "width": width,
                        "permutation": list(perm),
                        "fill_mode": fill_mode, "read_mode": read_mode,
                        "mapped_count": result["mapped_count"],
                        "unmapped_count": 0,
                        "coverage": cov["coverage"],
                        "words": cov["words"],
                        "longest": cov["longest"],
                        "anchor_hits": ah,
                        "project_score": bd["total"],
                        "phase": "transposition_mono",
                        "mapping": {k: v for k, v in sorted(result["mapping"].items())},
                    })
                    if cov["coverage"] > 0.30:
                        print(f"  *** GOOD: kw={kw} w={width} {fill_mode}->{read_mode} "
                              f"cov={cov['coverage']:.1%} ah={ah} "
                              f"words={cov['words'][:5]}")

                elif n_unc <= 4:
                    # Exhaustively try all permutations of unmapped_plain
                    # assigned to unmapped_cipher
                    best_cov = 0.0
                    best_text = ""
                    best_assignment = ()

                    for perm_assign in iter_perms(range(len(result["unmapped_plain"]))):
                        text = apply_full_substitution(
                            inter, result["mapping"],
                            result["unmapped_cipher"],
                            result["unmapped_plain"],
                            perm_assign)
                        cov = word_coverage(text, trie)
                        if cov["coverage"] > best_cov:
                            best_cov = cov["coverage"]
                            best_text = text
                            best_assignment = perm_assign

                    ah = anchor_hits(best_text)
                    cov = word_coverage(best_text, trie)
                    bd = build_score_breakdown(best_text)
                    full_mapping = dict(result["mapping"])
                    for i, ci in enumerate(result["unmapped_cipher"]):
                        full_mapping[ci] = result["unmapped_plain"][best_assignment[i]]

                    all_results.append({
                        "text": best_text,
                        "keyword": kw, "width": width,
                        "permutation": list(perm),
                        "fill_mode": fill_mode, "read_mode": read_mode,
                        "mapped_count": result["mapped_count"],
                        "unmapped_count": n_unc,
                        "coverage": best_cov,
                        "words": cov["words"],
                        "longest": cov["longest"],
                        "anchor_hits": ah,
                        "project_score": bd["total"],
                        "phase": "transposition_mono",
                        "mapping": {k: v for k, v in sorted(full_mapping.items())},
                    })
                    if best_cov > 0.30:
                        print(f"  *** GOOD: kw={kw} w={width} {fill_mode}->{read_mode} "
                              f"cov={best_cov:.1%} ah={ah} unc={n_unc} "
                              f"words={cov['words'][:5]}")

    elapsed = time.perf_counter() - t0
    print(f"\n  Checked {phase1_checked}, consistent {phase1_consistent}, "
          f"{len(all_results)} results, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 2: Extended search — all permutations for small widths
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 2: Exhaustive permutations for widths 2-8")
    print("=" * 72)

    phase2_checked = 0
    phase2_consistent = 0

    for width in range(2, 9):
        max_perms = 5040 if width <= 7 else 2000
        seen = set()
        # All permutations for small widths
        perm_source = iter_perms(range(width)) if width <= 7 else []
        count = 0
        for perm in perm_source:
            if count >= max_perms:
                break
            count += 1
            if perm in seen:
                continue
            seen.add(perm)

            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)
                phase2_checked += 1

                result = check_mono_consistency(inter)
                if result is None:
                    continue
                phase2_consistent += 1
                n_unc = len(result["unmapped_cipher"])

                if n_unc > 4:
                    continue

                if n_unc == 0:
                    text = apply_substitution(inter, result["mapping"])
                else:
                    best_cov = 0.0
                    best_text = ""
                    best_assign = ()
                    for pa in iter_perms(range(len(result["unmapped_plain"]))):
                        t = apply_full_substitution(
                            inter, result["mapping"],
                            result["unmapped_cipher"],
                            result["unmapped_plain"], pa)
                        c = word_coverage(t, trie)
                        if c["coverage"] > best_cov:
                            best_cov = c["coverage"]
                            best_text = t
                            best_assign = pa
                    text = best_text

                cov = word_coverage(text, trie)
                ah = anchor_hits(text)
                bd = build_score_breakdown(text)

                full_mapping = dict(result["mapping"])
                if n_unc > 0:
                    for i, ci in enumerate(result["unmapped_cipher"]):
                        full_mapping[ci] = result["unmapped_plain"][best_assign[i]]

                all_results.append({
                    "text": text,
                    "keyword": f"perm{perm}", "width": width,
                    "permutation": list(perm),
                    "fill_mode": fill_mode, "read_mode": read_mode,
                    "mapped_count": result["mapped_count"],
                    "unmapped_count": n_unc,
                    "coverage": cov["coverage"],
                    "words": cov["words"],
                    "longest": cov["longest"],
                    "anchor_hits": ah,
                    "project_score": bd["total"],
                    "phase": "exhaustive_perm",
                    "mapping": {k: v for k, v in sorted(full_mapping.items())},
                })
                if cov["coverage"] > 0.35:
                    print(f"  *** HIT: w={width} perm={perm} {fill_mode}->{read_mode} "
                          f"cov={cov['coverage']:.1%} ah={ah} unc={n_unc}")

        elapsed = time.perf_counter() - t0
        print(f"  width={width}: checked {phase2_checked}, consistent {phase2_consistent}, "
              f"results {len(all_results)}, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 3: Reverse order — substitution first, then transposition
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 3: Reverse order (substitution → transposition)")
    print("=" * 72)

    # If encryption was: plaintext → substitution → transposition → ciphertext
    # Then: ciphertext position j came from substituted position enc_map[j]
    # And substituted[i] = sub(plaintext[i])
    # So ciphertext[j] = transposition of substituted text
    #
    # We know plaintext[p] for anchor positions p.
    # After substitution: substituted[p] = sub(plaintext[p])
    # After transposition: these land at various ciphertext positions.
    #
    # Approach: for each transposition, compute where each plaintext
    # position ends up in the ciphertext. Then check if the mapping
    # ciphertext_char → plaintext_char is consistent as a substitution.

    phase3_checked = 0
    phase3_consistent = 0

    for kw in keywords[:15]:
        for width in range(2, 16):
            perm = keyword_permutation(kw, width)
            for fill_mode, read_mode in [("row", "column")]:
                phase3_checked += 1

                # Build encryption mapping
                cells = set(existing_cells(N, width))
                f_cells = fill_order(cells, fill_mode, False, False)
                r_cells = read_order(cells, read_mode, perm, False, False)
                cell_to_plain = {f_cells[i]: i for i in range(N)}
                # enc_map[j] = plain position that ends up at ciphertext position j
                enc_map = [cell_to_plain[r_cells[j]] for j in range(N)]

                # For known plaintext at position p:
                # sub(plaintext[p]) ends up at ciphertext position where enc_map[j] == p
                # So: K4[j] should equal sub(KNOWN_PT[p]) for j where enc_map[j] == p
                # i.e.: sub is a mapping from plaintext char to ciphertext char at the
                # transposed position

                # Build inv: for plain position p, what ciphertext position j?
                plain_to_ct: dict[int, int] = {}
                for j in range(N):
                    plain_to_ct[enc_map[j]] = j

                # Check mono consistency in the substitution direction
                # sub(plain_char) = ciphertext_char at transposed position
                mapping: dict[str, str] = {}  # plain_char -> cipher_char
                reverse: dict[str, str] = {}  # cipher_char -> plain_char
                valid = True

                for pos, plain_ch in KNOWN_PT.items():
                    ct_pos = plain_to_ct.get(pos)
                    if ct_pos is None:
                        valid = False
                        break
                    ct_ch = K4[ct_pos]

                    if plain_ch in mapping:
                        if mapping[plain_ch] != ct_ch:
                            valid = False
                            break
                    else:
                        mapping[plain_ch] = ct_ch

                    if ct_ch in reverse:
                        if reverse[ct_ch] != plain_ch:
                            valid = False
                            break
                    else:
                        reverse[ct_ch] = plain_ch

                if not valid:
                    continue

                phase3_consistent += 1
                # Invert: we need cipher_char -> plain_char for decryption
                # First undo transposition, then apply reverse substitution
                inv_sub = reverse  # cipher_char -> plain_char

                unmapped_ct = [c for c in STANDARD_ALPHABET if c not in inv_sub]
                unmapped_pt = [c for c in STANDARD_ALPHABET if c not in mapping]
                n_unc = len(unmapped_ct)

                if n_unc > 4:
                    continue

                # Decrypt: undo transposition first
                detrans = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)

                # Wait — in reverse order, we undo transposition first to get
                # the substituted text, then undo substitution.
                # Actually for reverse order encryption (sub then trans):
                # decrypt = undo_trans then undo_sub
                # undo_sub uses inv_sub: substituted_char -> plain_char

                if n_unc == 0:
                    text = "".join(inv_sub.get(c, "?") for c in detrans)
                    best_assign = ()
                else:
                    best_cov = 0.0
                    best_text = ""
                    best_assign = ()
                    for pa in iter_perms(range(n_unc)):
                        full_inv = dict(inv_sub)
                        for i, ci in enumerate(unmapped_ct):
                            full_inv[ci] = unmapped_pt[pa[i]]
                        t = "".join(full_inv.get(c, "?") for c in detrans)
                        c = word_coverage(t, trie)
                        if c["coverage"] > best_cov:
                            best_cov = c["coverage"]
                            best_text = t
                            best_assign = pa
                    text = best_text

                cov = word_coverage(text, trie)
                ah = anchor_hits(text)
                bd = build_score_breakdown(text)

                full_inv = dict(inv_sub)
                if n_unc > 0:
                    for i, ci in enumerate(unmapped_ct):
                        full_inv[ci] = unmapped_pt[best_assign[i]]

                all_results.append({
                    "text": text,
                    "keyword": kw, "width": width,
                    "permutation": list(perm),
                    "fill_mode": fill_mode, "read_mode": read_mode,
                    "mapped_count": len(inv_sub),
                    "unmapped_count": n_unc,
                    "coverage": cov["coverage"],
                    "words": cov["words"],
                    "longest": cov["longest"],
                    "anchor_hits": ah,
                    "project_score": bd["total"],
                    "phase": "reverse_mono",
                    "mapping": {k: v for k, v in sorted(full_inv.items())},
                })
                if cov["coverage"] > 0.35:
                    print(f"  *** HIT: kw={kw} w={width} {fill_mode}->{read_mode} "
                          f"cov={cov['coverage']:.1%} ah={ah} unc={n_unc}")

    elapsed = time.perf_counter() - t0
    print(f"\n  Checked {phase3_checked}, consistent {phase3_consistent}, "
          f"results {len(all_results)}, {elapsed:.1f}s")

    # ===================================================================
    # RESULTS
    # ===================================================================
    all_results.sort(key=lambda x: (-x["coverage"], -x["anchor_hits"]))

    elapsed = time.perf_counter() - t0
    print(f"\n{'=' * 72}")
    print(f"FINAL RESULTS ({elapsed:.1f}s, {len(all_results)} candidates)")
    print("=" * 72)

    for i, r in enumerate(all_results[:30]):
        print(f"#{i+1:>2} cov={r['coverage']:.1%} ah={r['anchor_hits']:>2} "
              f"proj={r['project_score']:>3} unc={r['unmapped_count']} "
              f"w={r['width']:>2} kw={r['keyword'][:12]:<12} "
              f"phase={r['phase']}")
        print(f"     words: {' '.join(r['words'][:8])}")
        print(f"     text:  {r['text'][:70]}...")

    # Detailed top 10
    print(f"\n{'=' * 72}")
    print("DETAILED TOP 10")
    print("=" * 72)
    for i, r in enumerate(all_results[:10]):
        print(f"\n--- #{i+1} ---")
        print(f"Phase: {r['phase']}")
        print(f"Trans: kw={r['keyword']} width={r['width']} perm={r['permutation']}")
        print(f"       fill={r['fill_mode']} read={r['read_mode']}")
        print(f"Substitution: {r['mapped_count']} determined + {r['unmapped_count']} guessed")
        print(f"Mapping: {r['mapping']}")
        print(f"Text: {r['text']}")
        print(f"Coverage: {r['coverage']:.1%}, Words: {r['words']}")
        print(f"Score: {r['project_score']}/1000, Anchors: {r['anchor_hits']}/24")
        for clue, start in ANCHORS:
            end = start + len(clue)
            if end <= len(r["text"]):
                seg = r["text"][start:end]
                hits = sum(1 for a, b in zip(seg, clue) if a == b)
                status = "MATCH" if seg == clue else f"{hits}/{len(clue)}"
                print(f"  {clue:>13} at {start}: \"{seg}\" [{status}]")

    # Save
    output = {
        "strategy": "monoalphabetic_transposition",
        "total_candidates": len(all_results),
        "elapsed_seconds": elapsed,
        "phases": {
            "transposition_mono": sum(1 for r in all_results if r["phase"] == "transposition_mono"),
            "exhaustive_perm": sum(1 for r in all_results if r["phase"] == "exhaustive_perm"),
            "reverse_mono": sum(1 for r in all_results if r["phase"] == "reverse_mono"),
        },
        "top_results": [
            {k: v for k, v in r.items()}
            for r in all_results[:100]
        ],
    }
    with open("runs/monoalphabetic_transposition.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/monoalphabetic_transposition.json")


if __name__ == "__main__":
    main()
