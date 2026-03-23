"""Strategy 29: Dictionary-Based Full-Text Scoring.

The paradigm shift strategy. Instead of bigram MCMC (which overfits noise),
this scores candidates by how much of the plaintext consists of ACTUAL
ENGLISH WORDS.

The key insight: bigram scoring finds fragments like 'THER' 'TION' 'ATION'
everywhere, giving false high scores. Word coverage demands complete words
like 'INFORMATION' 'BETWEEN' 'POSITION' which random text almost never
contains. A candidate with 40%+ word coverage likely contains real English.

Phases:
1. Build word trie from ~2000 embedded English words
2. Rescore ALL existing candidates from previous runs
3. Fresh constraint-first sweep with word scoring (no MCMC)
4. Report candidates ranked by word coverage
"""
from __future__ import annotations

import sys
import os
import time
import json
import random
from itertools import product

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, ANCHOR_COMPONENT_CLUES, STANDARD_ALPHABET, KRYPTOS_ALPHABET,
)
from kryptos.common import (
    build_score_breakdown, decrypt_vigenere_standard, normalize_letters,
)
from kryptos.transposition import (
    periodic_transposition_decrypt, keyword_permutation,
)

# ---------------------------------------------------------------------------
# Known plaintext
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
# Embedded English dictionary (~2000 words, 3+ letters)
# Compact: one space-separated string, split at runtime
# ---------------------------------------------------------------------------
_WORDS_RAW = (
    # Kryptos-relevant
    "EAST NORTHEAST BERLIN CLOCK EGYPT TOMB CHAMBER PASSAGE CORRIDOR TUNNEL "
    "SECRET HIDDEN BURIED LOCATION COORDINATES LATITUDE LONGITUDE DEGREES "
    "MINUTES SECONDS NORTH WEST SOUTH MESSAGE DELIVER POSITION SHADOW LIGHT "
    "ILLUSION BETWEEN SUBTLE ABSENCE NUANCE INVISIBLE MAGNETIC FIELD "
    "INFORMATION GATHERED TRANSMITTED UNDERGROUND UNKNOWN LANGLEY SLOWLY "
    "DESPERATELY REMAINS DEBRIS TREMBLING HANDS BREACH CANDLE FLICKER "
    "EMERGED MIST ANYTHING CARTER HOWARD WONDERFUL THINGS DISCOVERY "
    "EXCAVATION ARCHAEOLOGY ANCIENT RUINS INSCRIPTION CIPHER DECODE "
    "ENCRYPT DECRYPT KEY ALPHABET CODE PUZZLE MYSTERY CLUE ANSWER "
    "SOLUTION TREASURE VAULT ARTIFACT MUSEUM STONE TABLET HIEROGLYPH "
    "PYRAMID TEMPLE DESERT OASIS RIVER NILE VALLEY PHARAOH QUEEN KING "
    "PALACE GARDEN FOUNTAIN STATUE COLUMN WALL GATE DOOR WINDOW FLOOR "
    "CEILING STEP STAIR ROOM HALL TOWER CLOCK SQUARE WORLD TIME "
    # Top English words (3+ letters)
    "THE AND FOR ARE BUT NOT YOU ALL ANY CAN HAD HER WAS ONE OUR OUT "
    "DAY GET HAS HIM HIS HOW ITS LET MAY NEW NOW OLD SEE WAY WHO BOY "
    "DID HER LET SAY SHE TOO USE DAD MOM THE AND THAT HAVE WITH THIS "
    "WILL YOUR FROM THEY BEEN CALL COME EACH FIND GIVE HAVE HIGH JUST "
    "KNOW LIKE LONG LOOK MAKE MANY MUCH MUST NAME OVER PART SUCH TAKE "
    "THAN THAT THEM THEN TURN VERY WANT WELL WHAT WHEN WILL WITH WORK "
    "YEAR ALSO BACK BEEN BOTH CAME COME DONE DOWN EVEN FACT FOUR GAVE "
    "GONE GOOD HAND HELP HERE HIGH HOME INTO JUST KEEP KIND LAST LEFT "
    "LIFE LINE LIST LIVE LONG MADE MAKE MANY MEAN MORE MOST MOVE MUCH "
    "MUST NEED NEXT ONCE ONLY OPEN OVER OWN PART PLAY POINT SAID SAME "
    "SEEM SHOW SIDE SOME SUCH SURE TELL THAN THEM THEN THEY THIS TIME "
    "TURN UPON USED VERY WANT WELL WENT WERE WHAT WHEN WILL WITH WORD "
    "ABOUT AFTER AGAIN BEING BELOW COULD EVERY FIRST FOUND GREAT GROUP "
    "HOUSE LARGE LATER LEARN NEVER OFTEN ORDER OTHER PLACE PLANT POINT "
    "RIGHT SHALL SINCE SMALL SOUND SPELL STILL STOOD STUDY THEIR THERE "
    "THESE THING THINK THOSE THREE UNDER UNTIL WATER WHERE WHICH WHILE "
    "WORLD WOULD WRITE YOUNG ABOVE ALONG BEGIN BELOW CARRY CAUSE CHILD "
    "CLOSE COVER CROSS EARLY EARTH EIGHT ENDED ENTER EQUAL EXACT EXIST "
    "EXTRA FIFTY FINAL FORCE GIVEN GREEN HEAVY HENCE HORSE HUMAN INNER "
    "ISSUE KNOWN LAYER LEVEL LOCAL MAJOR MATCH MEANT METAL MIGHT MONEY "
    "MONTH MOVED MUSIC NIGHT NORTH NOTED NOVEL OCCUR OUTER OWNER PAPER "
    "PARTY PEACE PLACE PLAIN POWER PRESS PRICE PRIDE PRIME PROOF PROVE "
    "QUICK QUITE RADIO RAISE RANGE RAPID REACH READY REFER RIGHT RIVER "
    "ROUND ROYAL SCENE SENSE SERVE SEVEN SHAPE SHARE SHORT SHOWN SIGHT "
    "SLEEP SMALL SMITH SOLID SOLVE SOUTH SPACE SPOKE STAGE STAND START "
    "STATE STILL STONE STORE STORY STUCK STUDY STYLE SUGAR SWEET TABLE "
    "TAKEN TEETH TENTH THEME THICK THIRD THROW TIGHT TITLE TODAY TOTAL "
    "TOUCH TOWER TRACK TRADE TRAIN TREAT TREND TRIAL TRIED TRUCK TRULY "
    "TRUST TRUTH TWICE UNDER UNION UNITE UNTIL UPPER UPSET URBAN USAGE "
    "USUAL VALID VALUE VISIT VITAL VOICE WASTE WATCH WATER WHEEL WHERE "
    "WHICH WHITE WHOLE WHOSE WOMEN WORLD WORSE WORST WORTH WOULD WRITE "
    "WRONG WROTE YOUTH "
    "ACROSS ACTION ADVISE AFFECT ALMOST ALWAYS AMOUNT ANIMAL ANSWER "
    "APPEAR AROUND ARRIVE ATTACK BECOME BEFORE BEHIND BETTER BEYOND "
    "BORDER BOTTOM BRANCH BREATH BRIDGE BROKEN CANNOT CAREER CAUGHT "
    "CAUSED CENTER CHANGE CHARGE CHOICE CHURCH CIRCLE CITIES CLOSED "
    "COFFEE COMING COMMON CORNER COUPLE COURSE DANGER DEALER DEBATE "
    "DECADE DECIDE DEGREE DEMAND DESERT DESIGN DETAIL DIRECT DIVIDE "
    "DOCTOR DRIVEN DURING EASILY EATING EFFECT EFFORT EIGHTH EMERGE "
    "EMPIRE ENABLE ENERGY ENGINE ENOUGH ENTIRE ESCAPE ESTATE ETHICS "
    "EVENTS EVOLVE EXCEPT EXPECT EXPERT EXTEND EXTENT FACING FACTOR "
    "FAIRLY FALLEN FAMILY FATHER FELLOW FIGURE FINGER FINISH FLIGHT "
    "FOLLOW FORCED FOREST FORGET FORMAL FORMER FOSSIL FOURTH FRIEND "
    "FUTURE GARDEN GATHER GENTLE GLOBAL GOLDEN GOTTEN GROUND GROWTH "
    "HAPPEN HARDLY HEALTH HEAVEN HIGHLY HONEST HORROR IMPACT IMPORT "
    "INCOME INDEED INFORM INJURY INSIDE INTENT ISLAND ITSELF JOINED "
    "JUNIOR KILLED LAUNCH LAWYER LEADER LENGTH LETTER LIGHTS LIKELY "
    "LIVING LOSING MARKED MARKET MASTER MATTER MEDIUM MEMBER MEMORY "
    "MENTAL METHOD MIDDLE MILLER MINING MINUTE MIRROR MODERN MOMENT "
    "MOTION MURDER MUSEUM MUTUAL NAMELY NARROW NATION NATIVE NATURE "
    "NEARBY NEARLY NEEDED NORMAL NOTICE NUMBER OBJECT OBTAIN OFFICE "
    "OPPOSE OPTION ORIGIN OUTPUT OXFORD PARENT PARTLY PASSED PATENT "
    "PEOPLE PERIOD PERMIT PERSON PLACED PLANET PLAYER PLEASE POCKET "
    "POLICY PREFER PUBLIC PURSUE RAISED RARELY RATHER READER REASON "
    "RECENT RECORD REDUCE REFORM REGARD REGIME REGION REJECT RELATE "
    "RELIEF REMAIN REMOTE REMOVE REPEAT REPORT RESIST RESULT RETAIN "
    "RETIRE RETURN REVEAL REVIEW RISING RULING SAFETY SALARY SAMPLE "
    "SCHEME SCHOOL SEARCH SECRET SECURE SELECT SENATE SENIOR SERIES "
    "SETTLE SEVERE SIGNAL SILENT SILVER SIMPLE SIMPLY SINGLE SLIGHT "
    "SMOOTH SOCIAL SOLELY SOURCE SPEECH SPIRIT SPREAD SPRING SQUARE "
    "STABLE STRAIN STRAND STREAM STREET STRESS STRICT STRIKE STRING "
    "STRONG STRUCK SUPPLY SURELY SURVEY SWITCH SYMBOL SYSTEM TAKING "
    "TARGET TAUGHT TEMPLE TENANT THIRTY THREAT THROWN TOWARD TRAVEL "
    "TREATY TRIBAL TWENTY UNIQUE UNLESS UPDATE USEFUL VALLEY VARIED "
    "VICTIM VISION VOLUME WALKER WEALTH WEEKLY WEIGHT WINTER WISDOM "
    "WITHIN WONDER WORKER WORTHY WRITER YELLOW "
    "ABILITY ABSENCE ACADEMY ACCOUNT ACHIEVE ACQUIRE ADDRESS ADVANCE "
    "ADVISED ALREADY ANCIENT ANOTHER APPLIED ARRANGE ARTICLE ATTEMPT "
    "AVERAGE BALANCE BARRIER BEARING BECAUSE BEDROOM BELIEVE BENEATH "
    "BESIDES BILLION BROUGHT CABINET CAPABLE CAPITAL CAPTAIN CAREFUL "
    "CARRIED CENTRAL CENTURY CERTAIN CHAPTER CHARGED CHARITY CHECKED "
    "CHICKEN CHRONIC CITIZEN CLAIMED CLASSIC CLIMATE CLOSEST CLOTHES "
    "COLLECT COLLEGE COMMAND COMMENT COMPANY COMPARE COMPLEX CONCERN "
    "CONDUCT CONFIRM CONNECT CONSIST CONTACT CONTAIN CONTENT CONTEXT "
    "CONTROL CONVERT CORRECT COUNCIL COUNTER COUNTRY COURAGE COVERED "
    "CREATED CRICKET CULTURE CURRENT DEALING DECLARE DECLINE DEFENCE "
    "DELIVER DENSITY DEPOSIT DERIVED DESPITE DEVELOP DEVOTED DIGITAL "
    "DISEASE DISPLAY DISTANT DIVIDED DRAWING DRESSED DRIVING DROPPED "
    "EASTERN ECONOMY EDITION ELDERLY ELEMENT EMOTION ENABLED ENDLESS "
    "ENGAGED ENHANCE ENJOYED ENQUIRY EPISODE ESSENCE EXAMINE EXAMPLE "
    "EXCITED EXCLUDE EXECUTE EXHIBIT EXPENSE EXPLAIN EXPLOIT EXPLORE "
    "EXPOSED EXPRESS EXTREME FAILING FAILURE FASHION FEATURE FEELING "
    "FICTION FIGHTER FINALLY FINANCE FINDING FOREIGN FOREVER FORMULA "
    "FORTUNE FORWARD FOUNDED FREEDOM FURTHER GENETIC GENUINE GETTING "
    "GRANTED GROWING HABITAT HANGING HEADING HERSELF HIGHWAY HIMSELF "
    "HISTORY HOLDING HOLIDAY HONOUR HOUSING HOWEVER HUNDRED HUNTING "
    "HUSBAND ILLEGAL IMAGINE IMAGINE INITIAL INQUIRY INSTEAD INVOLVE "
    "KILLING KINGDOM KITCHEN KNOWING LANDING LARGELY LEADING LEARNED "
    "LENDING LIBERAL LIBRARY LICENCE LIMITED LINKING LISTING LOCALLY "
    "LOOKING MACHINE MANAGER MARRIED MASSIVE MEASURE MEDICAL MEETING "
    "MENTION MILITIA MILLION MINERAL MINIMUM MISSING MISSION MIXTURE "
    "MONITOR MONTHLY MORNING MYSTERY NATURAL NEITHER NETWORK NOTHING "
    "NUCLEAR OBVIOUS OFFICER OPINION ORGANIC OUTCOME OVERALL PACIFIC "
    "PAINFUL PARKING PARTIAL PARTNER PASSAGE PASSING PATIENT PATTERN "
    "PAYMENT PENALTY PENSION PERCENT PERFECT PERFORM PERHAPS PICTURE "
    "PLASTIC POINTED POPULAR PORTION POVERTY PRESENT PREVENT PRIMARY "
    "PRINTER PRIVATE PROBLEM PROCEED PROCESS PRODUCE PRODUCT PROFILE "
    "PROJECT PROMISE PROMOTE PROPOSE PROTECT PROTEIN PROTEST PROVIDE "
    "PUBLISH PURPOSE PUTTING QUALIFY QUARTER QUICKLY RADICAL RAILWAY "
    "READING REALITY RECEIVE RECOVER REFLECT REGULAR RELATED RELEASE "
    "REMAINS REMOVAL REMOVED REPLACE REQUEST REQUIRE RESERVE RESOLVE "
    "RESPECT RESPOND RESTORE REVENUE REVERSE ROLLING ROUTINE RUNNING "
    "SATISFY SCIENCE SECTION SEGMENT SERIOUS SERVICE SESSION SETTING "
    "SEVENTH SEVERAL SHELTER SILENCE SIMILAR SITTING SOCIETY SOLDIER "
    "SOMEONE SOMEHOW SPEAKER SPECIAL SPONSOR STADIUM STARTED STATION "
    "STORAGE STRANGE STRETCH SUCCESS SUGGEST SUPPORT SUPPOSE SURFACE "
    "SURVIVE SUSPECT TEACHER TENSION THEATRE THERAPY THEREBY THOUGHT "
    "THROUGH TONIGHT TOTALLY TOURISM TOWARDS TRAFFIC TROUBLE TURNING "
    "TYPICAL UNIFORM UNKNOWN UNUSUAL UPWARDS VARIETY VEHICLE VERSION "
    "VETERAN VILLAGE VIOLENT VIRTUAL VISIBLE WARNING WEATHERWEBLOG "
    "WEBSITE WELCOME WESTERN WHETHER WILLING WITHOUT WRITING "
    "ABSOLUTE ACCEPTED ACCIDENT ACCURATE ACHIEVED ACQUIRED ACTUALLY "
    "ADEQUATE ADJUSTED ADMITTED ADVANCED AFFECTED ALLIANCE ALTHOUGH "
    "ANALYSIS ANNOUNCE ANYTHING ANYWHERE APPARENT APPROACH APPROVAL "
    "ARGUMENT ASSEMBLY ASSUMING ATTACHED ATTEMPTS AUDIENCE AUTONOMY "
    "BACTERIA BALANCED BARGAIN BASEBALL BATHROOM BECOMING BELIEVED "
    "BIRTHDAY BLOCKING BOUNDARY BREAKING BRINGING BUILDING BUSINESS "
    "CALENDAR CAMPAIGN CAPACITY CAPTURED CARRYING CASUALTY CATEGORY "
    "CEREMONY CHAIRMAN CHAMPION CHANGING CHEMICAL CHILDREN CHOOSING "
    "CIVILIAN CLEARING CLIMBING CLINICAL CLOTHING COACHING COLLAPSE "
    "COMBINED COMEBACK COMEDIAN COMMERCE COMPARED COMPLETE COMPOSED "
    "COMPUTER CONCLUDE CONCRETE CONFLICT CONGRESS CONSIDER CONSTANT "
    "CONSUMER CONTAINS CONTINUE CONTRAST CONVINCE CORRIDOR COVERAGE "
    "CREATIVE CRIMINAL CRITICAL CROSSING CULTURAL CURRENCY CUSTOMER "
    "DAUGHTER DEADLINE DECEMBER DECISION DECLARED DECREASE DEFEATED "
    "DEFINING DEFINITE DELIVERY DEMANDED DESIGNER DETAILED DIABETES "
    "DIALOGUE DIRECTED DIRECTOR DISABLED DISCOVER DISCRETE DISORDER "
    "DISPATCH DISTINCT DISTRICT DOCTRINE DOCUMENT DOMESTIC DOMINANT "
    "DONATION DRAMATIC DRINKING DROPPING DURATION ECONOMIC EDUCATED "
    "EDUCATOR ELECTION ELEGANCE ELEMENT ELEVATED EMERGING EMISSION "
    "EMPHASIS EMPLOYED EMPLOYEE EMPLOYER ENCLOSED ENCODING ENORMOUS "
    "ENTIRELY ENTITLED ENTRANCE ENVELOPE EQUALITY EQUIPPED ESTIMATE "
    "EVALUATE EVIDENCE EVERYDAY EVERYONE EXCHANGE EXCITING EXCLUDED "
    "EXERCISE EXISTING EXPANDED EXPECTED EXPLICIT EXPLORED EXPOSURE "
    "EXTENDED EXTERNAL FACILITY FAMILIAR FAVORITE FEATURED FEEDBACK "
    "FESTIVAL FIGHTING FILENAME FILMMAKER FINALIST FINALLY FINDINGS "
    "FINISHED FLOATING FOLLOWED FOOTBALL FORECAST FORMERLY FORMERLY "
    "FOUNDING FOURTEEN FRACTION FRAGMENT FREQUENT FRONTIER FUNCTION "
    "GENERATE GOVERNOR GRADUATE GRAPHICS GRATEFUL GREATEST GUARDIAN "
    "GUIDANCE HANDLING HAPPENED HARDWARE HERITAGE HIGHLAND HISTORIC "
    "HOMELAND HOMELESS HONESTLY HOSPITAL IDENTITY IDEOLOGY IGNORANT "
    "IMAGINED IMPERIAL IMPLICIT IMPORTED IMPOSING IMPROVED INCIDENT "
    "INCLUDED INCREASE INDICATE INDIRECT INDUSTRY INFORMAL INFORMED "
    "INHERENT INITIALLY INNOCENT INSPIRED INSTANCE INTEGRAL INTENDED "
    "INTERACT INTEREST INTERNAL INVASION INVENTOR INVESTED INVESTOR "
    "INVOLVED ISOLATED JUDGMENT JUNCTION KEYBOARD LANDMARK LANGUAGE "
    "LAUNCHED LEARNING LIFETIME LITERARY LOCATION MAGAZINE MAGNETIC "
    "MAINLAND MAINTAIN MAJORITY MANAGING MANIFEST MARGINAL MARRIAGE "
    "MATERIAL MEASURED MECHANIC MEDIEVAL MEMORIAL MERCHANT MIDNIGHT "
    "MILITARY MINISTER MINORITY MODERATE MOLECULE MOMENTUM MONOPOLY "
    "MOREOVER MORTGAGE MOVEMENT MULTIPLE MULTIPLY MUTATION NATIONAL "
    "NEGATIVE NINETEEN NORMALLY NORTHERN NOTEBOOK NOVEMBER NUMEROUS "
    "OBJECTIVE OBSTACLE OCCASION OCCUPIED OCCURRED OFFERING OFFICIAL "
    "OFFSHORE OLYMPICS OPPONENT OPPOSITE ORDINARY ORGANISM ORGANIZE "
    "ORIGINAL ORTHODOX OUTBREAK OVERCOME OVERLOOK OVERVIEW PAINTING "
    "PARALLEL PARENTAL PARTICLE PARTISAN PASSPORT PATIENCE PEACEFUL "
    "PECULIAR PERCEIVE PERSONAL PETITION PHYSICAL PLANNING PLATFORM "
    "PLEASANT PLEASURE PLUNGING POINTING POLICING POLICIES POLITICS "
    "POSSIBLE POSSIBLY POWERFUL PRACTICE PRECIOUS PREDATOR PREGNANT "
    "PRESENCE PRESERVE PRESSING PRESSURE PRESUMED PREVIOUS PRINCESS "
    "PRINTING PRIORITY PRISONER PROBABLY PROCEEDS PRODUCER PROFOUND "
    "PROGRESS PROMISED PROMPTLY PROPERLY PROPERTY PROPOSAL PROPOSED "
    "PROSPECT PROTOCOL PROVINCE PROVIDED PROVIDER PROVINCE PUBLICLY "
    "PURCHASE PURSUING QUANTITY QUESTION QUOTIENT REACTION RECEIVED "
    "RECENTLY RECOVERY REDUCING REFERRAL REFERRED REGIONAL REGISTER "
    "REGULATE RELATION RELATIVE RELEASED RELEVANT RELIABLE RELIGION "
    "REMEMBER RENOWNED REPEATED REPLACED REPORTED REPORTER REPUBLIC "
    "REQUIRED RESEARCH RESIDENT RESIGNED RESOLVED RESOURCE RESPONSE "
    "RESTORED RESULTED RETAINED RETIRING RETRIEVE RETURNED REVEALED "
    "REVERSAL REVIEWER REVISION RHETORIC RIGOROUS ROMANTIC SCENARIO "
    "SCHEDULE SCRUTINY SEASONAL SECONDLY SECURITY SELECTED SEMESTER "
    "SEQUENCE SETTLING SHOOTING SHOPPING SHORTAGE SHOULDER SHOWDOWN "
    "SHUTDOWN SIDEWALK SIGNALED SLIGHTLY SMUGGLED SNAPSHOT SOFTWARE "
    "SOMEBODY SOMETIME SOUTHERN SPEAKING SPECIFIC SPECTRUM SPENDING "
    "SPORTING STANDARD STANDING STICKING STIMULUS STOPPING STRAIGHT "
    "STRANGER STRATEGY STRENGTH STRIKING STRONGLY STRUGGLE STUNNING "
    "SUBURBAN SUDDENLY SUFFERED SUITABLE SUPERIOR SUPPLIED SUPPLIER "
    "SUPPOSED SURGICAL SURPRISE SURVIVAL SURVIVED SURVIVOR SUSPENSE "
    "SYMBOLIC SYMPATHY SYNDROME TEACHING TEAMMATE TERMINAL TERRIFIC "
    "THEOLOGY THIRTEEN THOROUGH THOUSAND THROWING TOGETHER TOMORROW "
    "TOUCHING TRACKING TRILLION TROPICAL TROUBLED ULTIMATE UMBRELLA "
    "UNCOMMON UNDERWAY UNIVERSE UNLAWFUL UNLIKELY UNSTABLE UPRISING "
    "VALIDATE VALUABLE VARIABLE VELOCITY VERTICAL VICINITY VIOLENCE "
    "VOLATILE WEAKNESS WARRANTY WATCHDOG WHATEVER WHENEVER WHEREVER "
    "WILDLIFE WIRELESS WITHDRAW WORKSHOP YOURSELF"
)

# ---------------------------------------------------------------------------
# Word trie for fast prefix/match lookup
# ---------------------------------------------------------------------------
class TrieNode:
    __slots__ = ("children", "is_word", "word")
    def __init__(self):
        self.children: dict[str, TrieNode] = {}
        self.is_word = False
        self.word = ""


def build_trie(words: list[str]) -> TrieNode:
    root = TrieNode()
    for w in words:
        node = root
        for ch in w:
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.is_word = True
        node.word = w
    return root


def word_coverage(text: str, trie: TrieNode, min_word_len: int = 3) -> dict:
    """Greedy longest-match word coverage.

    Scans left to right. At each position, finds the longest dictionary word
    starting there. Characters covered by words are marked. Returns coverage
    stats.
    """
    n = len(text)
    covered = [False] * n
    words_found: list[tuple[str, int]] = []  # (word, start_pos)

    pos = 0
    while pos < n:
        node = trie
        longest_word = ""
        longest_end = pos
        # Walk trie from pos
        for j in range(pos, n):
            ch = text[j]
            if ch not in node.children:
                break
            node = node.children[ch]
            if node.is_word and len(node.word) >= min_word_len:
                longest_word = node.word
                longest_end = j + 1

        if longest_word:
            words_found.append((longest_word, pos))
            for k in range(pos, longest_end):
                covered[k] = True
            pos = longest_end
        else:
            pos += 1

    covered_count = sum(covered)
    return {
        "coverage": covered_count / n if n > 0 else 0.0,
        "covered_chars": covered_count,
        "total_chars": n,
        "words_found": words_found,
        "num_words": len(words_found),
        "avg_word_len": (sum(len(w) for w, _ in words_found) / len(words_found)
                         if words_found else 0.0),
        "longest_word": max((w for w, _ in words_found), key=len, default=""),
        "word_list": [w for w, _ in words_found],
    }


def anchor_hits(text: str) -> int:
    hits = 0
    for clue, start in ANCHORS:
        end = start + len(clue)
        if end <= len(text):
            hits += sum(1 for a, b in zip(text[start:end], clue) if a == b)
    return hits


# ---------------------------------------------------------------------------
# Constraint-first consistency check
# ---------------------------------------------------------------------------
def check_vigenere_consistency(inter: str, period: int) -> list[int] | None:
    slot_reqs: dict[int, set[int]] = {}
    for pos, pch in KNOWN_PT.items():
        if pos >= len(inter):
            return None
        shift = (ord(inter[pos]) - ord(pch)) % 26
        slot = pos % period
        if slot not in slot_reqs:
            slot_reqs[slot] = set()
        slot_reqs[slot].add(shift)

    key_shifts = [-1] * period
    for slot, shifts in slot_reqs.items():
        if len(shifts) != 1:
            return None
        key_shifts[slot] = shifts.pop()
    return key_shifts


def decrypt_with_shifts(inter: str, shifts: list[int], period: int) -> str:
    return "".join(
        STANDARD_ALPHABET[(ord(inter[i]) - 65 - (shifts[i % period] if shifts[i % period] >= 0 else 0)) % 26]
        for i in range(len(inter)))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    t0 = time.perf_counter()

    # Build dictionary
    raw_words = set()
    for w in _WORDS_RAW.split():
        w = w.strip().upper()
        if len(w) >= 3 and all(c in STANDARD_ALPHABET for c in w):
            raw_words.add(w)
    word_list = sorted(raw_words)
    trie = build_trie(word_list)
    print(f"Dictionary: {len(word_list)} words loaded")

    # Sanity check
    test_cov = word_coverage("EASTNORTHEASTBERLINCLOCKTHEINFORMATION", trie)
    print(f"Sanity check: '{test_cov['word_list']}' coverage={test_cov['coverage']:.1%}")

    all_results: list[dict] = []

    # ===================================================================
    # PHASE 1: Rescore existing candidates from previous runs
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 1: Rescore existing candidates with word coverage")
    print("=" * 72)

    run_files = [
        "runs/constraint_first_deep.json",
        "runs/alt_substitution_sweep.json",
        "runs/latitude_investigation.json",
        "runs/digraphic_sweep.json",
    ]

    for rf in run_files:
        path = rf
        if not os.path.exists(path):
            print(f"  {rf}: not found, skipping")
            continue
        with open(path) as f:
            data = json.load(f)
        results = data.get("top_results", [])
        print(f"  {rf}: {len(results)} candidates")

        for r in results:
            text = r.get("text", "")
            if not text:
                continue
            cov = word_coverage(text, trie)
            bd = build_score_breakdown(text)
            ah = anchor_hits(text)

            all_results.append({
                "text": text,
                "source": rf,
                "coverage": cov["coverage"],
                "covered_chars": cov["covered_chars"],
                "num_words": cov["num_words"],
                "avg_word_len": cov["avg_word_len"],
                "longest_word": cov["longest_word"],
                "word_list": cov["word_list"],
                "anchor_hits": ah,
                "project_score": bd["total"],
                "anchor_score": bd["anchor"],
                "language_score": bd["language"],
                "key": r.get("key", ""),
                "cipher": r.get("cipher", "vigenere"),
                "vig_period": r.get("vig_period", 0),
                "width": r.get("width", 0),
                "permutation": r.get("permutation", []),
                "phase": "rescore_existing",
            })

            # Also try shifted anchor positions (-2 to +2)
            for shift in [-2, -1, 1, 2]:
                shifted = text[shift:] if shift > 0 else "?" * abs(shift) + text[:shift]
                if len(shifted) != len(text):
                    continue
                scov = word_coverage(shifted, trie)
                if scov["coverage"] > cov["coverage"] + 0.05:
                    all_results.append({
                        "text": shifted,
                        "source": rf + f" (shift={shift})",
                        "coverage": scov["coverage"],
                        "covered_chars": scov["covered_chars"],
                        "num_words": scov["num_words"],
                        "avg_word_len": scov["avg_word_len"],
                        "longest_word": scov["longest_word"],
                        "word_list": scov["word_list"],
                        "anchor_hits": anchor_hits(shifted),
                        "project_score": build_score_breakdown(shifted)["total"],
                        "anchor_score": 0,
                        "language_score": 0,
                        "key": r.get("key", ""),
                        "cipher": r.get("cipher", ""),
                        "vig_period": r.get("vig_period", 0),
                        "width": r.get("width", 0),
                        "permutation": r.get("permutation", []),
                        "phase": f"rescore_shifted_{shift}",
                    })

    elapsed = time.perf_counter() - t0
    print(f"  Rescored {len(all_results)} candidates, {elapsed:.1f}s")

    # ===================================================================
    # PHASE 2: Fresh constraint-first sweep with word scoring
    # ===================================================================
    print(f"\n{'=' * 72}")
    print("PHASE 2: Constraint-first sweep with word-coverage scoring")
    print("=" * 72)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "LONGITUDE",
        "BERLIN", "CLOCK", "SANBORN", "SHADOW", "EGYPT", "CARTER",
    ]

    phase2_checked = 0
    phase2_consistent = 0
    phase2_interesting = 0

    for kw in keywords:
        for width in [5, 6, 7, 8]:
            perm = keyword_permutation(kw, width)
            for fill_mode, read_mode in [("row", "column"), ("column", "row")]:
                inter = periodic_transposition_decrypt(
                    K4, width, perm,
                    fill_mode=fill_mode, read_mode=read_mode)

                for period in range(2, 50):
                    phase2_checked += 1
                    key_shifts = check_vigenere_consistency(inter, period)
                    if key_shifts is None:
                        continue
                    phase2_consistent += 1

                    unconstrained = [i for i in range(period) if key_shifts[i] < 0]
                    n_unc = len(unconstrained)

                    # Use random sampling for all cases (fast)
                    # For n_unc <= 3 (17K combos) do exhaustive; otherwise sample
                    rng = random.Random(width * 1000 + period + hash(kw))
                    best_cov = 0.0
                    best_text = ""
                    best_shifts = list(key_shifts)

                    if n_unc <= 3:
                        for combo in product(range(26), repeat=n_unc):
                            test_shifts = list(key_shifts)
                            for idx, slot in enumerate(unconstrained):
                                test_shifts[slot] = combo[idx]
                            text = decrypt_with_shifts(inter, test_shifts, period)
                            cov = word_coverage(text, trie)
                            if cov["coverage"] > best_cov:
                                best_cov = cov["coverage"]
                                best_text = text
                                best_shifts = list(test_shifts)
                    else:
                        n_samples = 5000 if n_unc <= 5 else 2000
                        for _ in range(n_samples):
                            test_shifts = list(key_shifts)
                            for slot in unconstrained:
                                test_shifts[slot] = rng.randrange(26)
                            text = decrypt_with_shifts(inter, test_shifts, period)
                            cov = word_coverage(text, trie)
                            if cov["coverage"] > best_cov:
                                best_cov = cov["coverage"]
                                best_text = text
                                best_shifts = list(test_shifts)

                    if best_cov > 0.20:
                        phase2_interesting += 1
                        cov = word_coverage(best_text, trie)
                        bd = build_score_breakdown(best_text)
                        key_str = "".join(STANDARD_ALPHABET[s] if s >= 0 else "?" for s in best_shifts)
                        all_results.append({
                            "text": best_text,
                            "source": "fresh_sweep",
                            "coverage": best_cov,
                            "covered_chars": cov["covered_chars"],
                            "num_words": cov["num_words"],
                            "avg_word_len": cov["avg_word_len"],
                            "longest_word": cov["longest_word"],
                            "word_list": cov["word_list"],
                            "anchor_hits": anchor_hits(best_text),
                            "project_score": bd["total"],
                            "anchor_score": bd["anchor"],
                            "language_score": bd["language"],
                            "key": key_str,
                            "cipher": "vigenere",
                            "vig_period": period,
                            "width": width,
                            "keyword": kw,
                            "permutation": list(perm),
                            "phase": "fresh_word_sweep",
                        })

        elapsed = time.perf_counter() - t0
        print(f"  {kw}: checked {phase2_checked}, consistent {phase2_consistent}, "
              f"interesting {phase2_interesting}, {elapsed:.1f}s")

    elapsed = time.perf_counter() - t0
    print(f"\nPhase 2 complete: {phase2_checked} checked, {phase2_consistent} consistent, "
          f"{phase2_interesting} interesting (>20% coverage), {elapsed:.1f}s")

    # ===================================================================
    # RESULTS
    # ===================================================================
    all_results.sort(key=lambda x: x["coverage"], reverse=True)

    print(f"\n{'=' * 72}")
    print(f"RESULTS BY WORD COVERAGE ({len(all_results)} total)")
    print("=" * 72)

    for i, r in enumerate(all_results[:40]):
        words_preview = " ".join(r["word_list"][:8])
        if len(r["word_list"]) > 8:
            words_preview += "..."
        tc = r.get("total_chars", N)
        print(f"#{i+1:>2} cov={r['coverage']:.1%} ({r['covered_chars']}/{tc}) "
              f"words={r['num_words']:>2} longest={r['longest_word']:<12} "
              f"ah={r['anchor_hits']:>2} proj={r['project_score']:>3} "
              f"src={r['source']}")
        print(f"     words: {words_preview}")
        print(f"     text:  {r['text'][:70]}...")

    # Flag interesting candidates
    interesting = [r for r in all_results if r["coverage"] > 0.25]
    if interesting:
        print(f"\n{'=' * 72}")
        print(f"INTERESTING CANDIDATES (coverage > 25%): {len(interesting)}")
        print("=" * 72)
        for r in interesting[:10]:
            print(f"\n  Coverage: {r['coverage']:.1%}, Words: {r['word_list']}")
            print(f"  Text: {r['text']}")
            print(f"  Source: {r['source']}, Anchors: {r['anchor_hits']}/24")
    else:
        print(f"\nNo candidates with >25% word coverage found.")

    # Baseline: what's the word coverage of random 97-char strings?
    rng = random.Random(42)
    random_coverages = []
    for _ in range(1000):
        rand_text = "".join(STANDARD_ALPHABET[rng.randrange(26)] for _ in range(97))
        rc = word_coverage(rand_text, trie)
        random_coverages.append(rc["coverage"])
    avg_random = sum(random_coverages) / len(random_coverages)
    max_random = max(random_coverages)
    print(f"\nBaseline: random 97-char string coverage: "
          f"mean={avg_random:.1%}, max={max_random:.1%}")

    # Save
    output = {
        "strategy": "dictionary_scoring",
        "dictionary_size": len(word_list),
        "total_candidates": len(all_results),
        "elapsed_seconds": elapsed,
        "random_baseline_mean": avg_random,
        "random_baseline_max": max_random,
        "phase2_stats": {
            "checked": phase2_checked,
            "consistent": phase2_consistent,
            "interesting": phase2_interesting,
        },
        "top_results": [
            {
                "rank": i + 1,
                "text": r["text"],
                "coverage": r["coverage"],
                "covered_chars": r["covered_chars"],
                "num_words": r["num_words"],
                "longest_word": r["longest_word"],
                "word_list": r["word_list"],
                "anchor_hits": r["anchor_hits"],
                "project_score": r["project_score"],
                "source": r["source"],
                "key": r.get("key", ""),
                "cipher": r.get("cipher", ""),
                "vig_period": r.get("vig_period", 0),
                "width": r.get("width", 0),
                "permutation": r.get("permutation", []),
                "phase": r["phase"],
            }
            for i, r in enumerate(all_results[:100])
        ],
    }
    with open("runs/dictionary_scoring.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to runs/dictionary_scoring.json")


if __name__ == "__main__":
    main()
