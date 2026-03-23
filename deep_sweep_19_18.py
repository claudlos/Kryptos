"""Deep sweep for strategies 18 and 19 with increased budgets.

Runs both strategies with more chains, more steps, wider parameter ranges,
and more random restarts to push beyond the initial 516/455 scores.
"""
from __future__ import annotations

import sys
import time
import random
import math
import json

sys.path.insert(0, ".")

from kryptos.constants import (
    K4, ANCHOR_COMPONENT_CLUES, KNOWN_PLAINTEXT_CLUES,
    STANDARD_ALPHABET, DEFAULT_KEYWORDS,
)
from kryptos.common import (
    anchor_alignment_score, language_shape_score, build_score_breakdown,
    build_ranked_candidate, dedupe_ranked_candidates, sort_ranked_candidates,
    decrypt_vigenere_standard,
)
from kryptos.transposition import (
    periodic_transposition_decrypt, keyword_permutation, identity_permutation,
)
from kryptos.runtime import StrategyRuntimeConfig

# ---------------------------------------------------------------------------
# Shared anchor data
# ---------------------------------------------------------------------------
ANCHORS = [(c, int(d["start_index"]) - 1) for c, d in ANCHOR_COMPONENT_CLUES.items()]
COMBINED = [(c, int(d["start_index"]) - 1) for c, d in KNOWN_PLAINTEXT_CLUES.items()]
KNOWN_PT: dict[int, str] = {}
for clue, start in ANCHORS:
    for i, ch in enumerate(clue):
        KNOWN_PT[start + i] = ch

# ---------------------------------------------------------------------------
# N-gram scorer (from strategy 19)
# ---------------------------------------------------------------------------
BIGRAM_LOG: dict[str, float] = {
    "TH": -1.22, "HE": -1.28, "IN": -1.44, "ER": -1.48, "AN": -1.52,
    "RE": -1.58, "ON": -1.65, "AT": -1.70, "EN": -1.72, "ND": -1.74,
    "TI": -1.76, "ES": -1.78, "OR": -1.80, "TE": -1.82, "OF": -1.84,
    "ED": -1.86, "IS": -1.88, "IT": -1.90, "AL": -1.92, "AR": -1.94,
    "ST": -1.96, "TO": -1.98, "NT": -2.00, "NG": -2.02, "SE": -2.04,
    "HA": -2.06, "AS": -2.08, "OU": -2.10, "IO": -2.12, "LE": -2.14,
    "VE": -2.16, "CO": -2.18, "ME": -2.20, "DE": -2.22, "HI": -2.24,
    "RI": -2.26, "RO": -2.28, "IC": -2.30, "NE": -2.32, "EA": -2.34,
    "RA": -2.36, "CE": -2.38, "LI": -2.40, "CH": -2.42, "LL": -2.44,
    "BE": -2.46, "MA": -2.48, "SI": -2.50, "OM": -2.52, "UR": -2.54,
    "CA": -2.56, "EL": -2.58, "TA": -2.60, "LA": -2.62, "NS": -2.64,
    "GE": -2.66, "LO": -2.68, "US": -2.70, "PE": -2.72, "EC": -2.74,
    "WA": -2.76, "WH": -2.78, "EE": -2.80, "NO": -2.82, "DO": -2.84,
    "TR": -2.86, "DI": -2.88, "WI": -2.90, "SO": -2.92, "IF": -2.94,
    "TT": -2.96, "LY": -2.98, "SS": -3.00, "FO": -3.02, "UL": -3.04,
    "CT": -3.06, "HO": -3.08, "OT": -3.10, "PR": -3.12, "SH": -3.14,
}
TRIGRAM_LOG: dict[str, float] = {
    "THE": -1.78, "AND": -2.15, "ING": -2.28, "ION": -2.52, "TIO": -2.56,
    "ENT": -2.60, "ERE": -2.68, "HER": -2.72, "ATE": -2.75, "VER": -2.78,
    "TER": -2.80, "THA": -2.82, "ATI": -2.84, "HAT": -2.86, "ALL": -2.88,
    "ETH": -2.90, "FOR": -2.92, "HIS": -2.94, "NOT": -2.96, "TED": -2.98,
    "EST": -3.00, "ERS": -3.02, "ITH": -3.04, "NTH": -3.06, "INT": -3.08,
    "ANT": -3.10, "ONE": -3.12, "OFT": -3.14, "STH": -3.16, "MEN": -3.18,
    "OUR": -3.20, "RED": -3.22, "IVE": -3.24, "NDE": -3.26, "OUN": -3.28,
    "IST": -3.30, "AIN": -3.32, "ORT": -3.34, "URE": -3.36, "STR": -3.38,
    "NES": -3.40, "AVE": -3.42, "ECT": -3.44, "RES": -3.46, "COM": -3.48,
    "PRO": -3.50, "ARE": -3.52, "OUT": -3.54, "WIT": -3.56, "EAR": -3.58,
}
OTHER_BG = -4.5
OTHER_TG = -5.5

def ngram_score(text: str) -> float:
    s = 0.0
    for i in range(len(text) - 1):
        s += BIGRAM_LOG.get(text[i:i+2], OTHER_BG)
    for i in range(len(text) - 2):
        s += TRIGRAM_LOG.get(text[i:i+3], OTHER_TG) * 1.5
    return s

def anchor_match_count(text: str) -> int:
    hits = 0
    for clue, start in ANCHORS:
        end = start + len(clue)
        if end <= len(text):
            hits += sum(1 for a, b in zip(text[start:end], clue) if a == b)
    return hits

def full_score(text: str) -> int:
    return anchor_alignment_score(text) + language_shape_score(text)

# ---------------------------------------------------------------------------
# MCMC chains with higher budgets
# ---------------------------------------------------------------------------
def mcmc_vigenere(ciphertext: str, period: int, rng: random.Random,
                  num_steps: int = 8000, init_temp: float = 6.0,
                  final_temp: float = 0.15) -> dict:
    n = len(ciphertext)
    shifts = [rng.randrange(26) for _ in range(period)]
    # Set known-plaintext constraints
    for pos, pc in KNOWN_PT.items():
        if pos < n:
            ci = STANDARD_ALPHABET.index(ciphertext[pos])
            pi = STANDARD_ALPHABET.index(pc)
            shifts[pos % period] = (ci - pi) % 26

    def decrypt(sh):
        return "".join(STANDARD_ALPHABET[(STANDARD_ALPHABET.index(ciphertext[i]) - sh[i % period]) % 26] for i in range(n))

    text = decrypt(shifts)
    score = ngram_score(text)
    best_shifts, best_score, best_text = list(shifts), score, text

    for step in range(num_steps):
        temp = init_temp - (init_temp - final_temp) * step / num_steps
        pos = rng.randrange(period)
        # Check if constrained
        constrained = False
        for kp_pos, kp_ch in KNOWN_PT.items():
            if kp_pos < n and kp_pos % period == pos:
                constrained = True
                break
        if constrained:
            continue
        old_shift = shifts[pos]
        new_shift = rng.randrange(26)
        shifts[pos] = new_shift
        new_text = decrypt(shifts)
        new_score = ngram_score(new_text)
        delta = (new_score - score) / max(temp, 0.01)
        if delta > 0 or rng.random() < math.exp(min(delta, 50)):
            score = new_score
            text = new_text
            if score > best_score:
                best_score = score
                best_shifts = list(shifts)
                best_text = text
        else:
            shifts[pos] = old_shift

    key = "".join(STANDARD_ALPHABET[s] for s in best_shifts)
    return {"text": best_text, "key": key, "period": period,
            "ngram_score": best_score, "anchor_hits": anchor_match_count(best_text),
            "full_score": full_score(best_text)}

def mcmc_transposition(ciphertext: str, width: int, rng: random.Random,
                       fill_mode: str = "row", read_mode: str = "column",
                       num_steps: int = 6000, init_temp: float = 5.0,
                       final_temp: float = 0.2) -> dict:
    n = len(ciphertext)
    perm = list(range(width))
    rng.shuffle(perm)

    def decrypt(p):
        return periodic_transposition_decrypt(ciphertext, width, tuple(p),
                                              fill_mode=fill_mode, read_mode=read_mode)

    text = decrypt(perm)
    score = ngram_score(text)
    best_perm, best_score, best_text = list(perm), score, text

    for step in range(num_steps):
        temp = init_temp - (init_temp - final_temp) * step / num_steps
        i, j = rng.sample(range(width), 2)
        perm[i], perm[j] = perm[j], perm[i]
        new_text = decrypt(perm)
        new_score = ngram_score(new_text)
        delta = (new_score - score) / max(temp, 0.01)
        if delta > 0 or rng.random() < math.exp(min(delta, 50)):
            score = new_score
            text = new_text
            if score > best_score:
                best_score = score
                best_perm = list(perm)
                best_text = text
        else:
            perm[i], perm[j] = perm[j], perm[i]

    return {"text": best_text, "permutation": best_perm, "width": width,
            "fill_mode": fill_mode, "read_mode": read_mode,
            "ngram_score": best_score, "anchor_hits": anchor_match_count(best_text),
            "full_score": full_score(best_text)}

def mcmc_combined(ciphertext: str, period: int, width: int, rng: random.Random,
                  fill_mode: str = "row", read_mode: str = "column",
                  num_steps: int = 10000, init_temp: float = 7.0,
                  final_temp: float = 0.1) -> dict:
    n = len(ciphertext)
    perm = list(range(width))
    rng.shuffle(perm)
    shifts = [rng.randrange(26) for _ in range(period)]

    def decrypt(p, sh):
        trans_text = periodic_transposition_decrypt(ciphertext, width, tuple(p),
                                                    fill_mode=fill_mode, read_mode=read_mode)
        return "".join(STANDARD_ALPHABET[(STANDARD_ALPHABET.index(trans_text[i]) - sh[i % period]) % 26]
                       for i in range(len(trans_text)))

    text = decrypt(perm, shifts)
    score = ngram_score(text)
    best_perm, best_shifts, best_score, best_text = list(perm), list(shifts), score, text

    for step in range(num_steps):
        temp = init_temp - (init_temp - final_temp) * step / num_steps
        if rng.random() < 0.5:
            # Mutate transposition
            i, j = rng.sample(range(width), 2)
            perm[i], perm[j] = perm[j], perm[i]
            new_text = decrypt(perm, shifts)
            new_score = ngram_score(new_text)
            delta = (new_score - score) / max(temp, 0.01)
            if delta > 0 or rng.random() < math.exp(min(delta, 50)):
                score = new_score
                text = new_text
                if score > best_score:
                    best_score, best_perm, best_shifts, best_text = score, list(perm), list(shifts), text
            else:
                perm[i], perm[j] = perm[j], perm[i]
        else:
            # Mutate Vigenere
            pos = rng.randrange(period)
            old_shift = shifts[pos]
            shifts[pos] = rng.randrange(26)
            new_text = decrypt(perm, shifts)
            new_score = ngram_score(new_text)
            delta = (new_score - score) / max(temp, 0.01)
            if delta > 0 or rng.random() < math.exp(min(delta, 50)):
                score = new_score
                text = new_text
                if score > best_score:
                    best_score, best_perm, best_shifts, best_text = score, list(perm), list(shifts), text
            else:
                shifts[pos] = old_shift

    key = "".join(STANDARD_ALPHABET[s] for s in best_shifts)
    return {"text": best_text, "key": key, "period": period,
            "permutation": best_perm, "width": width,
            "fill_mode": fill_mode, "read_mode": read_mode,
            "ngram_score": best_score, "anchor_hits": anchor_match_count(best_text),
            "full_score": full_score(best_text)}

# ---------------------------------------------------------------------------
# Alternating optimization with higher budgets
# ---------------------------------------------------------------------------
def alternating_opt(ciphertext: str, period: int, width: int, rng: random.Random,
                    kw_seed: str = "KRYPTOS",
                    num_restarts: int = 8, max_rounds: int = 8,
                    vig_iters: int = 80, trans_swaps: int = 60) -> dict:
    n = len(ciphertext)
    best_overall = {"score": -1, "text": "", "key": "", "perm": []}

    for restart in range(num_restarts):
        # Initialize transposition
        if restart == 0:
            perm = list(keyword_permutation(kw_seed, width))
        else:
            perm = list(range(width))
            rng.shuffle(perm)

        # Initialize Vigenere key
        shifts = [rng.randrange(26) for _ in range(period)]
        # Seed from known plaintext where possible
        for pos, pc in KNOWN_PT.items():
            if pos < n:
                slot = pos % period
                ci = STANDARD_ALPHABET.index(ciphertext[pos])
                pi = STANDARD_ALPHABET.index(pc)
                required = (ci - pi) % 26
                shifts[slot] = required

        current_best_sc = -float("inf")
        for _round in range(max_rounds):
            # Phase A: Fix transposition, optimize Vigenere
            trans_text = periodic_transposition_decrypt(
                ciphertext, width, tuple(perm), fill_mode="row", read_mode="column")

            for _vi in range(vig_iters):
                pos = rng.randrange(period)
                constrained = any(kp % period == pos for kp in KNOWN_PT if kp < n)
                if constrained:
                    continue
                best_s, best_sc = shifts[pos], -float("inf")
                for s in range(26):
                    shifts[pos] = s
                    text = "".join(
                        STANDARD_ALPHABET[(STANDARD_ALPHABET.index(trans_text[i]) - shifts[i % period]) % 26]
                        for i in range(n))
                    sc = ngram_score(text)
                    if sc > best_sc:
                        best_sc = sc
                        best_s = s
                shifts[pos] = best_s
                if best_sc > current_best_sc:
                    current_best_sc = best_sc

            # Phase B: Fix Vigenere, optimize transposition
            for _ts in range(trans_swaps):
                i, j = rng.sample(range(width), 2)
                perm[i], perm[j] = perm[j], perm[i]
                trans_text = periodic_transposition_decrypt(
                    ciphertext, width, tuple(perm), fill_mode="row", read_mode="column")
                text = "".join(
                    STANDARD_ALPHABET[(STANDARD_ALPHABET.index(trans_text[k]) - shifts[k % period]) % 26]
                    for k in range(n))
                new_sc = ngram_score(text)
                if new_sc > current_best_sc:
                    current_best_sc = new_sc
                else:
                    perm[i], perm[j] = perm[j], perm[i]

        # Final text
        trans_text = periodic_transposition_decrypt(
            ciphertext, width, tuple(perm), fill_mode="row", read_mode="column")
        final_text = "".join(
            STANDARD_ALPHABET[(STANDARD_ALPHABET.index(trans_text[i]) - shifts[i % period]) % 26]
            for i in range(n))
        final_score = full_score(final_text)

        if final_score > best_overall["score"]:
            best_overall = {
                "score": final_score,
                "text": final_text,
                "key": "".join(STANDARD_ALPHABET[s] for s in shifts),
                "perm": list(perm),
                "period": period,
                "width": width,
                "anchor_hits": anchor_match_count(final_text),
            "full_score": final_score,
            }

    return best_overall


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------
def main():
    config = StrategyRuntimeConfig()
    rng = random.Random(42)
    all_candidates = []
    t0 = time.perf_counter()

    # Deep MCMC sweep - Vigenere only
    print("=== Phase 1: Deep MCMC Vigenere chains ===")
    vig_periods = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 24, 97]
    for period in vig_periods:
        for chain in range(6):
            r = mcmc_vigenere(K4, period, rng, num_steps=8000,
                              init_temp=4.0 + chain * 1.0,
                              final_temp=0.08 + chain * 0.05)
            all_candidates.append(r)
        elapsed = time.perf_counter() - t0
        best_so_far = max(all_candidates, key=lambda x: x["full_score"])
        print(f"  period={period:>2}: best_full={best_so_far['full_score']}, "
              f"best_anchor_hits={best_so_far['anchor_hits']}, elapsed={elapsed:.1f}s")

    # Deep MCMC sweep - transposition only
    print("\n=== Phase 2: Deep MCMC Transposition chains ===")
    trans_widths = [5, 7, 8, 9, 10, 11, 12, 14, 16, 19, 21, 24, 27, 32]
    for width in trans_widths:
        for fm, rm in [("row", "column"), ("column", "row")]:
            for chain in range(4):
                r = mcmc_transposition(K4, width, rng, fill_mode=fm, read_mode=rm,
                                       num_steps=6000,
                                       init_temp=4.0 + chain * 1.2,
                                       final_temp=0.15 + chain * 0.05)
                all_candidates.append(r)
        elapsed = time.perf_counter() - t0
        best_so_far = max(all_candidates, key=lambda x: x["full_score"])
        print(f"  width={width:>2}: best_full={best_so_far['full_score']}, elapsed={elapsed:.1f}s")

    # Deep MCMC sweep - combined
    print("\n=== Phase 3: Deep MCMC Combined chains ===")
    comb_periods = [5, 6, 7, 8, 10, 12, 14]
    comb_widths = [7, 9, 10, 12, 14]
    for period in comb_periods:
        for width in comb_widths:
            for fm, rm in [("row", "column"), ("column", "row")]:
                for chain in range(3):
                    r = mcmc_combined(K4, period, width, rng, fill_mode=fm, read_mode=rm,
                                      num_steps=10000,
                                      init_temp=6.0 + chain * 1.5,
                                      final_temp=0.08)
                    all_candidates.append(r)
        elapsed = time.perf_counter() - t0
        print(f"  period={period}, widths done: best_full={max(all_candidates, key=lambda x: x['full_score'])['full_score']}, elapsed={elapsed:.1f}s")

    # Deep alternating optimization
    print("\n=== Phase 4: Deep Alternating Optimization ===")
    alt_periods = [5, 6, 7, 8, 9, 10, 11, 12, 14]
    alt_widths = [7, 9, 10, 11, 12, 14, 21, 27]
    kw_seeds = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN"]
    for period in alt_periods:
        for width in alt_widths:
            for kw in kw_seeds[:3]:
                r = alternating_opt(K4, period, width, rng, kw_seed=kw,
                                    num_restarts=8, max_rounds=8,
                                    vig_iters=80, trans_swaps=60)
                all_candidates.append(r)
        elapsed = time.perf_counter() - t0
        best_so_far = max(all_candidates, key=lambda x: x["full_score"])
        print(f"  period={period}: best_full={best_so_far['full_score']}, elapsed={elapsed:.1f}s")

    # Final ranking
    elapsed = time.perf_counter() - t0
    print(f"\n=== RESULTS ({elapsed:.1f}s total, {len(all_candidates)} candidates) ===\n")

    # Sort by full_score descending
    ranked = sorted(all_candidates, key=lambda x: x["full_score"], reverse=True)

    # Show top 20
    for i, c in enumerate(ranked[:20]):
        text = c["text"]
        preview = text[:60] + "..." if len(text) > 60 else text
        mode = "vig" if "key" in c and "permutation" not in c else \
               "trans" if "permutation" in c and "key" not in c else "combined"
        info_parts = []
        if "key" in c:
            info_parts.append(f"key={c['key']}")
        if "period" in c:
            info_parts.append(f"p={c['period']}")
        if "width" in c:
            info_parts.append(f"w={c['width']}")
        if "permutation" in c:
            info_parts.append(f"perm={c['permutation'][:8]}...")
        info = ", ".join(info_parts)
        print(f"  #{i+1:>2} score={c['full_score']:>5} anchors={c['anchor_hits']:>2} "
              f"mode={mode:<8} {info}")
        print(f"       {preview}")

    # Build proper candidates using project infrastructure
    print("\n=== Building scored candidates ===")
    top_texts = []
    seen = set()
    for c in ranked[:30]:
        t = c["text"]
        if t not in seen:
            seen.add(t)
            top_texts.append(c)

    scored = []
    for c in top_texts[:15]:
        chain = []
        km = {}
        if "key" in c:
            chain.append(f"deep_sweep_vigenere:p={c.get('period','?')}:key={c['key']}")
            km["key"] = c["key"]
            km["period"] = c.get("period")
        if "permutation" in c:
            chain.append(f"deep_sweep_transposition:w={c.get('width','?')}")
            km["permutation"] = c.get("permutation")
            km["width"] = c.get("width")
        rc = build_ranked_candidate(
            c["text"],
            transform_chain=chain or ["deep_sweep"],
            scorer_profile="anchor-first",
            key_material=km,
        )
        scored.append(rc)
        print(f"  full_score={c['full_score']:>5} -> project_score={rc['total_score']}/1000  "
              f"anchor={rc['breakdown']['anchor']}  lang={rc['breakdown']['language']}")

    # Save results
    output = {
        "total_candidates": len(all_candidates),
        "elapsed_seconds": elapsed,
        "top_results": [
            {
                "rank": i + 1,
                "full_score": c["full_score"],
                "project_score": scored[i]["total_score"] if i < len(scored) else None,
                "anchor_hits": c["anchor_hits"],
                "text": c["text"],
                "key": c.get("key"),
                "period": c.get("period"),
                "width": c.get("width"),
                "permutation": c.get("permutation"),
            }
            for i, c in enumerate(top_texts[:15])
        ],
    }
    with open("runs/deep_sweep_19_18.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to runs/deep_sweep_19_18.json")


if __name__ == "__main__":
    main()
