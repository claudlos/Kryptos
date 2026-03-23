#!/usr/bin/env python3
"""Strategy 36: Anchor Position Sensitivity Analysis.

Sanborn's clues gave anchor positions verbally. What if they're off by 1 or 2?
This strategy re-runs a constraint-first Vigenere approach with shifted anchor
positions and reports which configurations produce the most consistent key
periods and highest scoring decrypts.

Test grid: EAST ±2, NORTHEAST ±2, BERLIN ±2, CLOCK ±2 → 5^4 = 625 configs.
"""
from __future__ import annotations

import itertools
import json
import math
import os
import random
import sys
import time
from collections import defaultdict

sys.path.insert(0, ".")

from kryptos.constants import K4, STANDARD_ALPHABET
from kryptos.common import (
    build_score_breakdown,
    decrypt_vigenere_standard,
    get_vigenere_shifts,
)
from kryptos.transposition import periodic_transposition_decrypt, keyword_permutation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

K4_LEN = len(K4)  # 97

# Original 0-indexed anchor positions
ORIGINAL_ANCHORS = {
    "EAST": (21, "EAST"),
    "NORTHEAST": (25, "NORTHEAST"),
    "BERLIN": (63, "BERLIN"),
    "CLOCK": (69, "CLOCK"),
}

# Shift range: original ± 2
SHIFT_RANGE = range(-2, 3)  # -2, -1, 0, 1, 2

# Transposition configs to test
TRANSPOSITION_CONFIGS = [
    {"name": "LATITUDE", "width": 6, "perm": (1, 5, 3, 0, 2, 4)},
]

# Additional keyword-based transpositions
KEYWORD_TRANS = [
    ("KRYPTOS", 6), ("KRYPTOS", 7), ("KRYPTOS", 8),
    ("PALIMPSEST", 6), ("PALIMPSEST", 7), ("PALIMPSEST", 8),
    ("ABSCISSA", 6), ("ABSCISSA", 7), ("ABSCISSA", 8),
]

for kw, w in KEYWORD_TRANS:
    perm = keyword_permutation(kw, w)
    TRANSPOSITION_CONFIGS.append({"name": f"{kw}_w{w}", "width": w, "perm": perm})

# Vigenere period range to check for consistency
PERIOD_RANGE = range(2, 51)

# MCMC parameters
MCMC_STEPS = 3000
MCMC_TEMP_START = 2.0
MCMC_TEMP_END = 0.05

# ---------------------------------------------------------------------------
# Embedded ~300-word dictionary for word coverage scoring
# ---------------------------------------------------------------------------

DICTIONARY = {
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN", "HER",
    "WAS", "ONE", "OUR", "OUT", "HAS", "HIS", "HOW", "ITS", "LET", "MAY",
    "NEW", "NOW", "OLD", "SEE", "WAY", "WHO", "DID", "GET", "HAS", "HIM",
    "HIS", "HOW", "MAN", "OUR", "SAY", "SHE", "TWO", "USE", "BOY", "DAY",
    "EYE", "GOT", "HAS", "LET", "PUT", "SAY", "TOO", "USE", "THAT", "WITH",
    "HAVE", "THIS", "WILL", "YOUR", "FROM", "THEY", "BEEN", "CALL", "COME",
    "EACH", "FIND", "GIVE", "GOOD", "HAVE", "HERE", "HIGH", "INTO", "JUST",
    "KEEP", "KNOW", "LAST", "LONG", "LOOK", "MADE", "MAKE", "MANY", "MORE",
    "MOST", "MUCH", "MUST", "NAME", "NEXT", "ONLY", "OVER", "PART", "SAID",
    "SAME", "SHOW", "SIDE", "SOME", "TAKE", "TELL", "THEM", "THEN", "TURN",
    "VERY", "WANT", "WELL", "WENT", "WHAT", "WHEN", "WORD", "WORK", "YEAR",
    "ABOUT", "AFTER", "AGAIN", "BEING", "BLACK", "BRING", "COULD", "COVER",
    "EARTH", "EVERY", "FIRST", "FOUND", "GIVEN", "GOING", "GREAT", "GROUP",
    "HOUSE", "LARGE", "LATER", "LEARN", "LIGHT", "MIGHT", "MONEY", "NEVER",
    "NIGHT", "NORTH", "OFTEN", "ORDER", "OTHER", "PLACE", "PLANT", "POINT",
    "RIGHT", "RIVER", "SHALL", "SMALL", "SOUTH", "SPELL", "STAND", "START",
    "STATE", "STILL", "STORY", "THEIR", "THERE", "THESE", "THING", "THINK",
    "THREE", "UNDER", "UNTIL", "WATER", "WHERE", "WHICH", "WHILE", "WHITE",
    "WORLD", "WOULD", "WRITE", "YOUNG", "BETWEEN", "BECAUSE", "ANOTHER",
    "THROUGH", "AGAINST", "COUNTRY", "GENERAL", "MORNING", "NOTHING",
    "PICTURE", "PROBLEM", "SEVERAL", "THOUGHT", "TOGETHER", "WESTERN",
    "WITHOUT", "ALREADY", "EVENING", "EXAMPLE", "HISTORY", "MILLION",
    "CERTAIN", "DELIVER", "MESSAGE", "PASSAGE", "CHAMBER",
    # Kryptos domain terms
    "EAST", "WEST", "NORTHEAST", "BERLIN", "CLOCK", "WALL", "WORLD",
    "EGYPT", "NILE", "GIZA", "TOMB", "VALLEY", "LUXOR", "PHARAOH",
    "SHADOW", "FORCES", "LANGLEY", "AGENCY", "SECRET", "HIDDEN",
    "BURIED", "LOCATION", "POSITION", "DEGREES", "MINUTES", "SECONDS",
    "LATITUDE", "LONGITUDE", "COORDINATE", "DIRECTION", "MAGNETIC",
    "FIELD", "UNDERGROUND", "UNKNOWN", "INVISIBLE", "ILLUSION",
    "PALIMPSEST", "ABSCISSA", "KRYPTOS", "CIPHER", "CODE", "DECODE",
    "ENCRYPT", "DECRYPT", "LAYER", "SUBTLE", "SHADING", "ABSENCE",
    "NUANCE", "IQLUSION", "CANDLE", "FLAME", "FLICKER", "BREACH",
    "CORNER", "DOORWAY", "PASSAGE", "DEBRIS", "REMAINS", "TREMBLING",
    "SLOWLY", "DESPERATELY", "INSERTED", "EMERGED", "PRESENTLY",
    "WIDENING", "ESCAPING", "ALEXANDER", "ALEXANDERPLATZ", "ZEITUHR",
    "REUNIFICATION", "CROWD", "HOWARD", "CARTER", "TUTANKHAMUN",
    "SAND", "DESERT", "PYRAMID", "ANCIENT", "TEMPLE", "EXPEDITION",
    "DISCOVERY", "ENTRANCE", "EXCAVATION", "INSCRIPTION",
    "TIME", "FACE", "HAND", "HOUR", "NEAR", "OPEN", "REAL", "SEEM",
    "MOVE", "LIVE", "HEAD", "NEED", "LAND", "LINE", "HOME", "BACK",
    "CITY", "TREE", "MARK", "PLAN", "ROAD", "FORM", "LEFT", "MILE",
    "ROCK", "SEND", "CARRY", "CROSS", "CLOSE", "REACH",
    "BELOW", "TABLE", "ALONG", "POWER", "CLEAR", "FRONT", "ABOVE",
}

# ---------------------------------------------------------------------------
# Bigram and trigram log-frequency tables (scaled log-probs ×1000)
# ---------------------------------------------------------------------------

_BIGRAM_PAIRS = (
    "TH:175 HE:164 IN:141 ER:139 AN:131 RE:126 ON:120 AT:117 EN:115 ND:113 "
    "TI:112 ES:111 OR:110 TE:108 OF:106 ED:104 IS:103 IT:102 AL:101 AR:100 "
    "ST:99 TO:98 NT:97 NG:96 SE:95 HA:94 AS:93 OU:92 IO:91 LE:90 "
    "VE:89 CO:88 ME:87 DE:86 HI:85 RI:84 RO:83 IC:82 NE:81 EA:80 "
    "RA:79 CE:78 LI:77 CH:76 LL:75 BE:74 MA:73 SI:72 OM:71 UR:70"
)
BIGRAM_LOG = {}
for pair in _BIGRAM_PAIRS.split():
    bg, val = pair.split(":")
    BIGRAM_LOG[bg] = int(val)

_TRIGRAM_TRIPLES = (
    "THE:200 AND:165 ING:158 ION:150 TIO:148 ENT:145 ERE:140 HER:138 "
    "ATE:135 VER:133 TER:130 THA:128 ATI:126 HAT:124 ERS:122 HIS:120 "
    "RES:118 ILL:116 ARE:114 CON:112 NCE:110 ALL:108 EVE:106 ITH:104 "
    "TED:102 AIN:100 EST:98 MAN:96 FOR:94 WAS:92"
)
TRIGRAM_LOG = {}
for triple in _TRIGRAM_TRIPLES.split():
    tg, val = triple.split(":")
    TRIGRAM_LOG[tg] = int(val)

# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def ngram_score(text: str) -> float:
    """Sum bigram + trigram log scores."""
    score = 0.0
    t = text.upper()
    for i in range(len(t) - 1):
        bg = t[i:i+2]
        if bg in BIGRAM_LOG:
            score += BIGRAM_LOG[bg]
    for i in range(len(t) - 2):
        tg = t[i:i+3]
        if tg in TRIGRAM_LOG:
            score += TRIGRAM_LOG[tg]
    return score


def dict_word_coverage(text: str) -> tuple[int, list[str]]:
    """Count how many dictionary words appear in text. Return count and list."""
    t = text.upper()
    found = []
    for word in DICTIONARY:
        if len(word) >= 3 and word in t:
            found.append(word)
    return len(found), found


def combined_score(text: str) -> float:
    """Combined score: ngram + dictionary coverage bonus."""
    ng = ngram_score(text)
    n_words, _ = dict_word_coverage(text)
    return ng + n_words * 50.0


# ---------------------------------------------------------------------------
# Anchor configuration builder
# ---------------------------------------------------------------------------

def build_known_plaintext(east_pos, ne_pos, berlin_pos, clock_pos):
    """Build a dict mapping 0-indexed position -> plaintext char for given anchors."""
    known = {}
    anchors = [
        (east_pos, "EAST"),
        (ne_pos, "NORTHEAST"),
        (berlin_pos, "BERLIN"),
        (clock_pos, "CLOCK"),
    ]
    for start, word in anchors:
        for i, ch in enumerate(word):
            pos = start + i
            if 0 <= pos < K4_LEN:
                known[pos] = ch
    return known


# ---------------------------------------------------------------------------
# Vigenere consistency check
# ---------------------------------------------------------------------------

def check_vigenere_consistency(transposed_ct: str, known_pt: dict, period: int):
    """Check if a Vigenere key of given period is consistent with known plaintext.
    
    Returns (is_consistent, key_slots, n_constrained) where:
    - is_consistent: True if no slot has contradictory shifts
    - key_slots: dict mapping slot_index -> shift value
    - n_constrained: number of key slots that are determined
    """
    key_slots = {}  # slot_index -> required shift
    for pos, plain_ch in known_pt.items():
        if pos >= len(transposed_ct):
            continue
        cipher_ch = transposed_ct[pos]
        if cipher_ch not in STANDARD_ALPHABET or plain_ch not in STANDARD_ALPHABET:
            continue
        shift = (STANDARD_ALPHABET.index(cipher_ch) - STANDARD_ALPHABET.index(plain_ch)) % 26
        slot = pos % period
        if slot in key_slots:
            if key_slots[slot] != shift:
                return False, {}, 0
        else:
            key_slots[slot] = shift
    return True, key_slots, len(key_slots)


def build_full_key(key_slots: dict, period: int) -> list[int]:
    """Build a full key, filling unconstrained slots with 0."""
    return [key_slots.get(i, 0) for i in range(period)]


# ---------------------------------------------------------------------------
# MCMC optimization for unconstrained key slots
# ---------------------------------------------------------------------------

def mcmc_optimize(transposed_ct: str, key_slots: dict, period: int,
                  steps: int = MCMC_STEPS) -> tuple[list[int], float, str]:
    """MCMC optimize unconstrained Vigenere key slots to maximize combined_score."""
    rng = random.Random(42)
    
    constrained = set(key_slots.keys())
    unconstrained = [i for i in range(period) if i not in constrained]
    
    if not unconstrained:
        # All slots determined
        key = build_full_key(key_slots, period)
        key_str = "".join(STANDARD_ALPHABET[s] for s in key)
        pt = decrypt_vigenere_standard(transposed_ct, key_str)
        return key, combined_score(pt), pt
    
    # Initialize unconstrained slots randomly
    current_key = dict(key_slots)
    for slot in unconstrained:
        current_key[slot] = rng.randint(0, 25)
    
    def decrypt_with_key(k):
        key_str = "".join(STANDARD_ALPHABET[k.get(i, 0)] for i in range(period))
        return decrypt_vigenere_standard(transposed_ct, key_str)
    
    current_pt = decrypt_with_key(current_key)
    current_score = combined_score(current_pt)
    
    best_key = dict(current_key)
    best_score = current_score
    best_pt = current_pt
    
    for step in range(steps):
        temp = MCMC_TEMP_START * ((MCMC_TEMP_END / MCMC_TEMP_START) ** (step / max(steps - 1, 1)))
        
        # Pick a random unconstrained slot and change it
        slot = rng.choice(unconstrained)
        old_val = current_key[slot]
        new_val = (old_val + rng.randint(1, 25)) % 26
        
        current_key[slot] = new_val
        candidate_pt = decrypt_with_key(current_key)
        candidate_score = combined_score(candidate_pt)
        
        delta = candidate_score - current_score
        if delta > 0 or rng.random() < math.exp(delta / max(temp * 100, 0.01)):
            current_score = candidate_score
            current_pt = candidate_pt
            if current_score > best_score:
                best_key = dict(current_key)
                best_score = current_score
                best_pt = candidate_pt
        else:
            current_key[slot] = old_val
    
    key_list = [best_key.get(i, 0) for i in range(period)]
    return key_list, best_score, best_pt


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def run_analysis():
    print("=" * 70)
    print("Strategy 36: Anchor Position Sensitivity Analysis")
    print("=" * 70)
    print(f"K4 length: {K4_LEN}")
    print(f"Anchor shift range: ±2 (5 positions each)")
    print(f"Total anchor configs: {5**4} = 625")
    print(f"Transposition configs: {len(TRANSPOSITION_CONFIGS)}")
    print(f"Period range: {PERIOD_RANGE.start}-{PERIOD_RANGE.stop - 1}")
    print(f"MCMC steps: {MCMC_STEPS}")
    print()
    
    start_time = time.time()
    
    # Generate all anchor shift combinations
    east_positions = [21 + d for d in SHIFT_RANGE]
    ne_positions = [25 + d for d in SHIFT_RANGE]
    berlin_positions = [63 + d for d in SHIFT_RANGE]
    clock_positions = [69 + d for d in SHIFT_RANGE]
    
    all_configs = list(itertools.product(east_positions, ne_positions, berlin_positions, clock_positions))
    print(f"Generated {len(all_configs)} anchor configurations")
    
    # Results storage
    results = {
        "strategy": "36_anchor_sensitivity",
        "description": "Anchor Position Sensitivity Analysis",
        "k4": K4,
        "original_anchors_0idx": {"EAST": 21, "NORTHEAST": 25, "BERLIN": 63, "CLOCK": 69},
        "shift_range": list(SHIFT_RANGE),
        "transposition_configs": [{"name": c["name"], "width": c["width"], "perm": list(c["perm"])} for c in TRANSPOSITION_CONFIGS],
        "period_range": [PERIOD_RANGE.start, PERIOD_RANGE.stop - 1],
        "mcmc_steps": MCMC_STEPS,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    
    # Phase 1: Consistency sweep across all 625 configs × all transpositions
    print("\n--- Phase 1: Consistency Sweep ---")
    print(f"Testing {len(all_configs)} anchor configs × {len(TRANSPOSITION_CONFIGS)} transpositions × {len(PERIOD_RANGE)} periods...")
    
    # For each transposition, find which anchor configs have the most consistent periods
    trans_results = {}
    
    # We'll limit detailed MCMC to top configs per transposition to keep runtime manageable
    TOP_CONFIGS_FOR_MCMC = 10  # Per transposition, run MCMC on top N configs
    
    total_combos = len(all_configs) * len(TRANSPOSITION_CONFIGS)
    combo_count = 0
    
    for t_idx, trans_cfg in enumerate(TRANSPOSITION_CONFIGS):
        t_name = trans_cfg["name"]
        t_width = trans_cfg["width"]
        t_perm = tuple(trans_cfg["perm"])
        
        # Decrypt K4 with this transposition
        transposed_ct = periodic_transposition_decrypt(K4, t_width, t_perm)
        
        config_scores = []  # (anchor_config, n_consistent_periods, total_constrained, details)
        
        for a_idx, (ep, nep, bp, cp) in enumerate(all_configs):
            known_pt = build_known_plaintext(ep, nep, bp, cp)
            
            # Map known_pt positions through the transposition
            # The transposition decrypts CT -> PT. So position i in transposed_ct
            # corresponds to position i in plaintext. But our known_pt positions
            # are in the ORIGINAL ciphertext space. We need to map them.
            #
            # Actually: the known_pt dict maps original plaintext positions to chars.
            # After transposition, the text is rearranged. We need to figure out
            # which positions in transposed_ct correspond to which original positions.
            #
            # periodic_transposition_decrypt takes ciphertext and produces plaintext.
            # If we think of it as: plaintext[i] = ciphertext[mapping[i]]
            # Then for Vigenere: ciphertext_for_vigenere = transposed_ct
            # And the known plaintext positions remain the same (they refer to
            # the final plaintext positions).
            #
            # Wait - let me think more carefully:
            # The model is: K4 = Vigenere(Transposition(plaintext))
            # So to decrypt: plaintext = InvTransposition(InvVigenere(K4))
            # Or equivalently: InvVigenere is applied to K4, then InvTransposition.
            #
            # But we can also think of it as:
            # Let intermediate = InvTransposition(K4) = transposed_ct
            # Then plaintext = InvVigenere(intermediate)
            #
            # No wait, the order matters. Let me reconsider:
            # If encryption is: CT = Transposition(Vigenere(PT, key))
            # Then decryption is: PT = InvVigenere(InvTransposition(CT), key)
            # So: intermediate = InvTransposition(CT)  [undo transposition]
            #     PT = InvVigenere(intermediate, key)   [undo Vigenere]
            #
            # Known plaintext at position i means PT[i] = known_ch.
            # intermediate[i] is what the Vigenere saw at position i.
            # So shift at slot (i % period) = (intermediate[i] - PT[i]) % 26.
            #
            # This is correct. The known_pt dict keys are plaintext positions
            # (same as intermediate positions since both are length K4_LEN).
            
            consistent_periods = []
            total_constrained = 0
            
            for period in PERIOD_RANGE:
                is_ok, key_slots, n_constr = check_vigenere_consistency(
                    transposed_ct, known_pt, period
                )
                if is_ok and n_constr > 0:
                    consistent_periods.append((period, n_constr))
                    total_constrained += n_constr
            
            config_label = f"E{ep}NE{nep}B{bp}C{cp}"
            shift_label = f"E{ep-21:+d}NE{nep-25:+d}B{bp-63:+d}C{cp-69:+d}"
            
            config_scores.append({
                "anchor_config": (ep, nep, bp, cp),
                "config_label": config_label,
                "shift_label": shift_label,
                "n_consistent": len(consistent_periods),
                "total_constrained": total_constrained,
                "consistent_periods": consistent_periods,
            })
            
            combo_count += 1
        
        # Sort by number of consistent periods (desc), then by total constrained (desc)
        config_scores.sort(key=lambda x: (x["n_consistent"], x["total_constrained"]), reverse=True)
        
        # Store summary
        trans_results[t_name] = {
            "transposition": {"name": t_name, "width": t_width, "perm": list(t_perm)},
            "top_configs": config_scores[:20],  # top 20
            "original_config_rank": None,
            "original_config_stats": None,
        }
        
        # Find where original config ranks
        for rank, cs in enumerate(config_scores):
            if cs["anchor_config"] == (21, 25, 63, 69):
                trans_results[t_name]["original_config_rank"] = rank + 1
                trans_results[t_name]["original_config_stats"] = cs
                break
        
        # Print summary for this transposition
        print(f"\n  [{t_name}] Top 5 anchor configs by consistent periods:")
        for i, cs in enumerate(config_scores[:5]):
            print(f"    #{i+1}: {cs['shift_label']} -> {cs['n_consistent']} consistent periods, "
                  f"{cs['total_constrained']} total constrained slots")
        
        orig = trans_results[t_name]["original_config_stats"]
        if orig:
            rank = trans_results[t_name]["original_config_rank"]
            print(f"    Original (E+0NE+0B+0C+0) rank: #{rank}/{len(config_scores)} "
                  f"({orig['n_consistent']} consistent, {orig['total_constrained']} constrained)")
    
    elapsed_phase1 = time.time() - start_time
    print(f"\nPhase 1 completed in {elapsed_phase1:.1f}s")
    
    # Phase 2: MCMC optimization on top configs for LATITUDE transposition
    print("\n--- Phase 2: MCMC Optimization on Top Configs ---")
    
    mcmc_results = []
    
    # Focus on LATITUDE first, then sample from others
    priority_trans = ["LATITUDE"]
    secondary_trans = [c["name"] for c in TRANSPOSITION_CONFIGS if c["name"] != "LATITUDE"][:3]
    
    for t_name in priority_trans + secondary_trans:
        is_priority = t_name in priority_trans
        n_to_test = TOP_CONFIGS_FOR_MCMC if is_priority else 3
        
        t_cfg = next(c for c in TRANSPOSITION_CONFIGS if c["name"] == t_name)
        t_width = t_cfg["width"]
        t_perm = tuple(t_cfg["perm"])
        transposed_ct = periodic_transposition_decrypt(K4, t_width, t_perm)
        
        top_configs = trans_results[t_name]["top_configs"][:n_to_test]
        
        # Also ensure original config is included
        orig_in_top = any(cs["anchor_config"] == (21, 25, 63, 69) for cs in top_configs)
        if not orig_in_top:
            orig_stats = trans_results[t_name]["original_config_stats"]
            if orig_stats:
                top_configs.append(orig_stats)
        
        print(f"\n  [{t_name}] Running MCMC on {len(top_configs)} configs...")
        
        for cfg in top_configs:
            ep, nep, bp, cp = cfg["anchor_config"]
            known_pt = build_known_plaintext(ep, nep, bp, cp)
            
            # Find best consistent period for MCMC
            best_period_result = None
            best_period_score = -1
            
            # Test top 5 consistent periods (by constrained slots)
            sorted_periods = sorted(cfg["consistent_periods"], key=lambda x: x[1], reverse=True)
            
            for period, n_constr in sorted_periods[:5]:
                is_ok, key_slots, _ = check_vigenere_consistency(transposed_ct, known_pt, period)
                if not is_ok:
                    continue
                
                key, score, pt = mcmc_optimize(transposed_ct, key_slots, period, steps=MCMC_STEPS)
                
                # Also get build_score_breakdown
                try:
                    breakdown = build_score_breakdown(pt)
                except Exception:
                    breakdown = {"total": 0}
                
                n_words, word_list = dict_word_coverage(pt)
                
                result = {
                    "transposition": t_name,
                    "anchor_config": list(cfg["anchor_config"]),
                    "shift_label": cfg["shift_label"],
                    "period": period,
                    "n_constrained": n_constr,
                    "n_unconstrained": period - n_constr,
                    "key": [int(k) for k in key],
                    "key_str": "".join(STANDARD_ALPHABET[k] for k in key),
                    "mcmc_score": round(score, 1),
                    "breakdown": breakdown,
                    "dict_words_found": n_words,
                    "dict_words_list": sorted(word_list)[:30],
                    "plaintext_preview": pt[:80],
                    "plaintext_full": pt,
                }
                
                total = breakdown.get("total", 0) + score
                
                if total > best_period_score:
                    best_period_score = total
                    best_period_result = result
            
            if best_period_result:
                mcmc_results.append(best_period_result)
                is_orig = cfg["anchor_config"] == (21, 25, 63, 69)
                marker = " [ORIGINAL]" if is_orig else ""
                print(f"    {cfg['shift_label']}{marker}: period={best_period_result['period']}, "
                      f"mcmc={best_period_result['mcmc_score']:.0f}, "
                      f"breakdown_total={best_period_result['breakdown'].get('total', 0)}, "
                      f"words={best_period_result['dict_words_found']}, "
                      f"key={best_period_result['key_str'][:20]}...")
    
    # Sort MCMC results by combined score
    mcmc_results.sort(key=lambda r: r["mcmc_score"] + r["breakdown"].get("total", 0), reverse=True)
    
    elapsed_phase2 = time.time() - start_time
    print(f"\nPhase 2 completed in {elapsed_phase2:.1f}s total")
    
    # Phase 3: Detailed analysis of top results
    print("\n--- Phase 3: Top Results Analysis ---")
    print()
    
    # Show top 15 results
    for i, res in enumerate(mcmc_results[:15]):
        total = res["mcmc_score"] + res["breakdown"].get("total", 0)
        is_orig = res["anchor_config"] == [21, 25, 63, 69]
        marker = " *** ORIGINAL ***" if is_orig else ""
        print(f"  #{i+1}: [{res['transposition']}] {res['shift_label']}{marker}")
        print(f"       Period={res['period']}, Key={res['key_str']}")
        print(f"       MCMC score={res['mcmc_score']:.0f}, Breakdown total={res['breakdown'].get('total', 0)}")
        print(f"       Combined={total:.0f}, Dict words={res['dict_words_found']}")
        print(f"       Words: {', '.join(res['dict_words_list'][:15])}")
        print(f"       PT: {res['plaintext_preview']}")
        print()
    
    # Phase 4: Sensitivity summary
    print("\n--- Phase 4: Sensitivity Summary ---")
    
    # For LATITUDE, build a sensitivity map
    lat_results = trans_results.get("LATITUDE", {})
    if lat_results:
        top20 = lat_results["top_configs"][:20]
        
        # Count which shift directions appear most in top configs
        shift_counts = defaultdict(int)
        for cfg in top20:
            ep, nep, bp, cp = cfg["anchor_config"]
            shift_counts[f"EAST_{ep-21:+d}"] += 1
            shift_counts[f"NE_{nep-25:+d}"] += 1
            shift_counts[f"BERLIN_{bp-63:+d}"] += 1
            shift_counts[f"CLOCK_{cp-69:+d}"] += 1
        
        print("\n  LATITUDE: Shift direction frequency in top-20 configs:")
        for anchor_name in ["EAST", "NE", "BERLIN", "CLOCK"]:
            counts = [(k, v) for k, v in shift_counts.items() if k.startswith(anchor_name + "_")]
            counts.sort(key=lambda x: x[1], reverse=True)
            print(f"    {anchor_name}: {', '.join(f'{k}={v}' for k, v in counts)}")
    
    # Original vs shifted: which is better?
    orig_mcmc = [r for r in mcmc_results if r["anchor_config"] == [21, 25, 63, 69]]
    shifted_better = [r for r in mcmc_results 
                      if r["anchor_config"] != [21, 25, 63, 69]
                      and (orig_mcmc and r["mcmc_score"] + r["breakdown"].get("total", 0) > 
                           orig_mcmc[0]["mcmc_score"] + orig_mcmc[0]["breakdown"].get("total", 0))]
    
    print(f"\n  Configs scoring higher than original: {len(shifted_better)}")
    if shifted_better:
        print(f"  Best shifted config: {shifted_better[0]['shift_label']} "
              f"(combined={shifted_better[0]['mcmc_score'] + shifted_better[0]['breakdown'].get('total', 0):.0f})")
    if orig_mcmc:
        print(f"  Original config score: combined={orig_mcmc[0]['mcmc_score'] + orig_mcmc[0]['breakdown'].get('total', 0):.0f}")
    
    # Finalize results
    results["phase1_consistency"] = {}
    for t_name, tr in trans_results.items():
        results["phase1_consistency"][t_name] = {
            "original_rank": tr["original_config_rank"],
            "original_stats": {
                "n_consistent": tr["original_config_stats"]["n_consistent"] if tr["original_config_stats"] else 0,
                "total_constrained": tr["original_config_stats"]["total_constrained"] if tr["original_config_stats"] else 0,
            } if tr["original_config_stats"] else None,
            "top5": [
                {
                    "shift_label": c["shift_label"],
                    "n_consistent": c["n_consistent"],
                    "total_constrained": c["total_constrained"],
                }
                for c in tr["top_configs"][:5]
            ],
        }
    
    results["phase2_mcmc_top15"] = [
        {
            "rank": i + 1,
            "transposition": r["transposition"],
            "anchor_config": r["anchor_config"],
            "shift_label": r["shift_label"],
            "period": r["period"],
            "key_str": r["key_str"],
            "mcmc_score": r["mcmc_score"],
            "breakdown_total": r["breakdown"].get("total", 0),
            "combined_score": round(r["mcmc_score"] + r["breakdown"].get("total", 0), 1),
            "dict_words_found": r["dict_words_found"],
            "dict_words_top10": r["dict_words_list"][:10],
            "plaintext_preview": r["plaintext_preview"],
            "is_original_anchors": r["anchor_config"] == [21, 25, 63, 69],
        }
        for i, r in enumerate(mcmc_results[:15])
    ]
    
    results["sensitivity_summary"] = {
        "n_shifted_configs_better_than_original": len(shifted_better),
        "best_shifted_label": shifted_better[0]["shift_label"] if shifted_better else None,
        "best_shifted_score": round(shifted_better[0]["mcmc_score"] + shifted_better[0]["breakdown"].get("total", 0), 1) if shifted_better else None,
        "original_score": round(orig_mcmc[0]["mcmc_score"] + orig_mcmc[0]["breakdown"].get("total", 0), 1) if orig_mcmc else None,
    }
    
    results["runtime_seconds"] = round(time.time() - start_time, 1)
    
    # Save results
    os.makedirs("runs", exist_ok=True)
    out_path = "runs/anchor_sensitivity.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    
    total_time = time.time() - start_time
    print(f"\n{'=' * 70}")
    print(f"Strategy 36 complete in {total_time:.1f}s")
    print(f"Results saved to {out_path}")
    print(f"{'=' * 70}")
    
    return results


if __name__ == "__main__":
    run_analysis()
