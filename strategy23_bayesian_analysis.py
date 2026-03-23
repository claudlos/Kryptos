"""Bayesian cipher analysis for K4.

Implements Bayesian posterior inference over cipher keys using:
  1. Uniform prior P(key)
  2. Likelihood from English bigram log-probabilities as language model
  3. Hard constraints from known plaintext positions
  4. Gibbs sampling to sample from posterior distributions

For each Vigenere period (2-20):
  - Runs a 2000-step Gibbs sampler
  - Tracks posterior frequency of each key letter at each position
  - Reports periods with high posterior concentration (low entropy)
  - Decrypts with MAP (maximum a posteriori) key and scores
"""

from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_ranked_candidate,
    build_score_breakdown,
    build_strategy_result,
    calculate_ioc,
    decrypt_vigenere_standard,
    dedupe_ranked_candidates,
    normalize_letters,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    K4,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig

import math
import random

SPEC = get_strategy_spec("23")

# ---------------------------------------------------------------------------
# Known plaintext anchors (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# EAST at 21-24, NORTHEAST at 25-33, BERLIN at 63-68, CLOCK at 69-73
KNOWN_PLAINTEXT: dict[int, str] = {}
for _clue, _start in ANCHORS:
    for _offset, _char in enumerate(_clue):
        KNOWN_PLAINTEXT[_start + _offset] = _char

# ---------------------------------------------------------------------------
# English bigram log-probabilities (top 50, from published frequencies)
# Frequencies are percentages; we convert to log-probabilities.
# ---------------------------------------------------------------------------
_BIGRAM_FREQ_PCT: dict[str, float] = {
    "TH": 3.56, "HE": 3.07, "IN": 2.43, "ER": 2.05, "AN": 1.99,
    "RE": 1.85, "ON": 1.76, "AT": 1.49, "EN": 1.45, "ND": 1.35,
    "TI": 1.34, "ES": 1.34, "OR": 1.28, "TE": 1.27, "OF": 1.17,
    "ED": 1.17, "IS": 1.13, "IT": 1.12, "AL": 1.09, "AR": 1.07,
    "ST": 1.05, "TO": 1.05, "NT": 1.04, "NG": 0.95, "SE": 0.93,
    "HA": 0.93, "AS": 0.87, "OU": 0.87, "IO": 0.83, "LE": 0.83,
    "VE": 0.83, "CO": 0.79, "ME": 0.79, "DE": 0.76, "HI": 0.73,
    "RI": 0.73, "RO": 0.73, "IC": 0.70, "NE": 0.69, "EA": 0.69,
    "RA": 0.62, "CE": 0.65, "LI": 0.62, "CH": 0.60, "LL": 0.58,
    "MA": 0.57, "CA": 0.53, "EL": 0.51, "TA": 0.53, "SI": 0.55,
}

# Total percentage covered by top 50 bigrams
_TOTAL_TOP_PCT = sum(_BIGRAM_FREQ_PCT.values())
# Remaining percentage spread across other bigrams
_REMAINING_PCT = 100.0 - _TOTAL_TOP_PCT
_NUM_OTHER_BIGRAMS = 26 * 26 - len(_BIGRAM_FREQ_PCT)
_OTHER_BIGRAM_PCT = _REMAINING_PCT / _NUM_OTHER_BIGRAMS if _NUM_OTHER_BIGRAMS > 0 else 0.01

# Build bigram log-probability lookup
BIGRAM_LOG_PROB: dict[str, float] = {}
for bg, pct in _BIGRAM_FREQ_PCT.items():
    BIGRAM_LOG_PROB[bg] = math.log(pct / 100.0)
_OTHER_LOG_PROB = math.log(max(_OTHER_BIGRAM_PCT / 100.0, 1e-8))

# Precompute log-prob for all 676 bigrams
FULL_BIGRAM_LOG_PROB: dict[str, float] = {}
for a in STANDARD_ALPHABET:
    for b in STANDARD_ALPHABET:
        bg = a + b
        FULL_BIGRAM_LOG_PROB[bg] = BIGRAM_LOG_PROB.get(bg, _OTHER_LOG_PROB)


# ---------------------------------------------------------------------------
# Likelihood computation
# ---------------------------------------------------------------------------

def _bigram_log_likelihood(plaintext: str) -> float:
    """Compute total bigram log-probability of a plaintext string."""
    if len(plaintext) < 2:
        return -999.0
    score = 0.0
    for i in range(len(plaintext) - 1):
        bg = plaintext[i:i + 2]
        score += FULL_BIGRAM_LOG_PROB.get(bg, _OTHER_LOG_PROB)
    return score


def _vigenere_decrypt_char(cipher_char: str, shift: int) -> str:
    """Decrypt a single character with a given Vigenere shift."""
    ci = STANDARD_ALPHABET.index(cipher_char)
    return STANDARD_ALPHABET[(ci - shift) % 26]


def _vigenere_decrypt_with_shifts(ciphertext: str, shifts: list[int], period: int) -> str:
    """Decrypt ciphertext using shifts list with given period."""
    result = []
    for i, c in enumerate(ciphertext):
        result.append(_vigenere_decrypt_char(c, shifts[i % period]))
    return "".join(result)


# ---------------------------------------------------------------------------
# Known-plaintext constraints for Vigenere
# ---------------------------------------------------------------------------

def _derive_shift_constraints(ciphertext: str, period: int) -> dict[int, int]:
    """Derive required shift values at key positions from known plaintext.

    Returns dict mapping key_position -> required_shift.
    If a contradiction is found (same key position requires different shifts),
    returns empty dict to signal this period is incompatible.
    """
    constraints: dict[int, int] = {}
    for pos, plain_char in KNOWN_PLAINTEXT.items():
        if pos >= len(ciphertext):
            continue
        cipher_char = ciphertext[pos]
        required_shift = (STANDARD_ALPHABET.index(cipher_char) - STANDARD_ALPHABET.index(plain_char)) % 26
        key_pos = pos % period
        if key_pos in constraints:
            if constraints[key_pos] != required_shift:
                return {}  # Contradiction — period incompatible
        constraints[key_pos] = required_shift
    return constraints


# ---------------------------------------------------------------------------
# Gibbs sampler for Vigenere key
# ---------------------------------------------------------------------------

def _gibbs_vigenere(
    ciphertext: str,
    period: int,
    rng: random.Random,
    num_steps: int = 2000,
    temperature: float = 1.0,
) -> dict[str, object]:
    """Run Gibbs sampling for Vigenere key of given period.

    Returns posterior counts, MAP key, and decrypted text.
    """
    n = len(ciphertext)

    # Derive constraints from known plaintext
    constraints = _derive_shift_constraints(ciphertext, period)
    # constraints may be empty if period is incompatible

    # Initialize shifts: use constraints where available, random elsewhere
    shifts = [0] * period
    free_positions: list[int] = []
    for pos in range(period):
        if pos in constraints:
            shifts[pos] = constraints[pos]
        else:
            shifts[pos] = rng.randrange(26)
            free_positions.append(pos)

    if not free_positions:
        # All positions are constrained; just evaluate
        plaintext = _vigenere_decrypt_with_shifts(ciphertext, shifts, period)
        posterior_counts = [[0] * 26 for _ in range(period)]
        for pos in range(period):
            posterior_counts[pos][shifts[pos]] = num_steps
        key_str = "".join(STANDARD_ALPHABET[s] for s in shifts)
        ll = _bigram_log_likelihood(plaintext)
        return {
            "posterior_counts": posterior_counts,
            "map_key": key_str,
            "map_text": plaintext,
            "map_score": ll,
            "period": period,
            "is_constrained": True,
            "constraint_count": len(constraints),
            "free_positions": 0,
        }

    # Track posterior counts: posterior_counts[pos][shift] = count
    posterior_counts = [[0] * 26 for _ in range(period)]

    # Track best (MAP) state
    current_text = _vigenere_decrypt_with_shifts(ciphertext, shifts, period)
    current_ll = _bigram_log_likelihood(current_text)
    best_shifts = list(shifts)
    best_ll = current_ll
    best_text = current_text

    for step in range(num_steps):
        # Sample each free position conditioned on all others
        for pos in free_positions:
            # Compute conditional log-likelihood for each possible shift value
            log_probs = []
            for candidate_shift in range(26):
                shifts[pos] = candidate_shift
                # Only recompute bigrams affected by this position change
                # For efficiency, just compute full log-likelihood
                text = _vigenere_decrypt_with_shifts(ciphertext, shifts, period)
                ll = _bigram_log_likelihood(text)
                log_probs.append(ll / temperature)

            # Normalize and sample from conditional
            max_lp = max(log_probs)
            exp_probs = [math.exp(lp - max_lp) for lp in log_probs]
            total = sum(exp_probs)
            probs = [p / total for p in exp_probs]

            # Sample from categorical distribution
            u = rng.random()
            cumulative = 0.0
            chosen = 0
            for idx, p in enumerate(probs):
                cumulative += p
                if u <= cumulative:
                    chosen = idx
                    break

            shifts[pos] = chosen

        # Record posterior counts (after burn-in)
        if step >= num_steps // 4:  # skip first 25% as burn-in
            for pos in range(period):
                posterior_counts[pos][shifts[pos]] += 1

        # Update current state
        current_text = _vigenere_decrypt_with_shifts(ciphertext, shifts, period)
        current_ll = _bigram_log_likelihood(current_text)
        if current_ll > best_ll:
            best_ll = current_ll
            best_shifts = list(shifts)
            best_text = current_text

    key_str = "".join(STANDARD_ALPHABET[s] for s in best_shifts)
    return {
        "posterior_counts": posterior_counts,
        "map_key": key_str,
        "map_text": best_text,
        "map_score": best_ll,
        "period": period,
        "is_constrained": bool(constraints),
        "constraint_count": len(constraints),
        "free_positions": len(free_positions),
    }


# ---------------------------------------------------------------------------
# Posterior analysis
# ---------------------------------------------------------------------------

def _posterior_entropy(counts: list[int]) -> float:
    """Compute entropy of a posterior distribution from counts."""
    total = sum(counts)
    if total == 0:
        return math.log2(26)  # max entropy if no data
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _posterior_map(counts: list[int]) -> int:
    """Return the MAP (most probable) value from counts."""
    return max(range(len(counts)), key=lambda i: counts[i])


def _posterior_concentration(counts: list[int]) -> float:
    """Return the probability of the MAP value (posterior concentration)."""
    total = sum(counts)
    if total == 0:
        return 1.0 / 26
    return max(counts) / total


def _analyze_posterior(result: dict[str, object]) -> dict[str, object]:
    """Analyze posterior distribution for quality indicators."""
    posterior_counts = result["posterior_counts"]
    period = int(result["period"])

    position_entropies = []
    position_concentrations = []
    position_map_letters = []

    for pos in range(period):
        counts = posterior_counts[pos]
        ent = _posterior_entropy(counts)
        conc = _posterior_concentration(counts)
        map_val = _posterior_map(counts)
        position_entropies.append(ent)
        position_concentrations.append(conc)
        position_map_letters.append(STANDARD_ALPHABET[map_val])

    avg_entropy = sum(position_entropies) / period if period > 0 else math.log2(26)
    avg_concentration = sum(position_concentrations) / period if period > 0 else 1.0 / 26
    min_entropy = min(position_entropies) if position_entropies else math.log2(26)
    max_concentration = max(position_concentrations) if position_concentrations else 1.0 / 26

    # A period is a strong candidate if average entropy is low
    # Max possible entropy for uniform over 26 is log2(26) ≈ 4.70
    # Strong candidate: avg entropy < 3.0 (well-constrained)
    quality = "strong" if avg_entropy < 2.5 else "moderate" if avg_entropy < 3.5 else "weak"

    return {
        "period": period,
        "avg_entropy": avg_entropy,
        "min_entropy": min_entropy,
        "avg_concentration": avg_concentration,
        "max_concentration": max_concentration,
        "position_entropies": position_entropies,
        "position_concentrations": position_concentrations,
        "map_key": "".join(position_map_letters),
        "quality": quality,
        "constraint_count": int(result["constraint_count"]),
        "free_positions": int(result["free_positions"]),
    }


# ---------------------------------------------------------------------------
# Gibbs sampler for substitution cipher
# ---------------------------------------------------------------------------

def _gibbs_substitution(
    ciphertext: str,
    rng: random.Random,
    num_steps: int = 400,
    temperature: float = 1.0,
) -> dict[str, object]:
    """Run Gibbs sampling for a simple substitution cipher.

    Maintains a permutation mapping ciphertext letters to plaintext letters.
    Uses integer arrays for performance.
    """
    n = len(ciphertext)

    # Convert ciphertext to integer array once
    ct_ints = [ord(c) - 65 for c in ciphertext]

    # Precompute bigram log-prob lookup table (26x26 array)
    _bg_table = [[_OTHER_LOG_PROB] * 26 for _ in range(26)]
    for bg, lp in FULL_BIGRAM_LOG_PROB.items():
        _bg_table[ord(bg[0]) - 65][ord(bg[1]) - 65] = lp

    # Initialize with random permutation
    perm = list(range(26))
    rng.shuffle(perm)

    # Apply known plaintext constraints to seed the permutation
    _kp_constraints: list[tuple[int, int]] = []  # (cipher_int, plain_int)
    for pos, plain_char in KNOWN_PLAINTEXT.items():
        if pos >= n:
            continue
        ci = ct_ints[pos]
        pi = ord(plain_char) - 65
        _kp_constraints.append((ci, pi))
        current_target = perm[ci]
        if current_target != pi:
            source = perm.index(pi)
            perm[ci], perm[source] = perm[source], perm[ci]

    # Precompute which cipher-letter indices are constrained
    _constrained_cipher_ints = {ci for ci, _ in _kp_constraints}
    _constraint_map = {ci: pi for ci, pi in _kp_constraints}

    # Compute current plaintext ints and score
    pt_ints = [perm[c] for c in ct_ints]

    def _fast_ll(pt: list[int]) -> float:
        s = 0.0
        for k in range(len(pt) - 1):
            s += _bg_table[pt[k]][pt[k + 1]]
        return s

    current_ll = _fast_ll(pt_ints)
    best_perm = list(perm)
    best_ll = current_ll
    best_pt = list(pt_ints)

    # Track posterior
    posterior_counts = [[0] * 26 for _ in range(26)]
    burn_in = num_steps // 4

    for step in range(num_steps):
        i = rng.randrange(26)
        j = rng.randrange(26)
        while j == i:
            j = rng.randrange(26)

        # Quick constraint check: if swapping would break a constrained mapping, skip
        violates = False
        if i in _constrained_cipher_ints:
            if perm[j] != _constraint_map.get(i, perm[j]):
                violates = True
        if not violates and j in _constrained_cipher_ints:
            if perm[i] != _constraint_map.get(j, perm[i]):
                violates = True
        if violates:
            continue

        # Swap and recompute affected plaintext positions
        old_pi = perm[i]
        old_pj = perm[j]
        perm[i], perm[j] = perm[j], perm[i]

        # Update pt_ints in-place
        for k in range(n):
            c = ct_ints[k]
            if c == i:
                pt_ints[k] = perm[i]
            elif c == j:
                pt_ints[k] = perm[j]

        proposed_ll = _fast_ll(pt_ints)

        # Metropolis acceptance
        delta = (proposed_ll - current_ll) / temperature
        if delta > 0 or rng.random() < math.exp(min(delta, 50)):
            current_ll = proposed_ll
            if current_ll > best_ll:
                best_ll = current_ll
                best_perm = list(perm)
                best_pt = list(pt_ints)
        else:
            # Reject — undo
            perm[i], perm[j] = perm[j], perm[i]
            for k in range(n):
                c = ct_ints[k]
                if c == i:
                    pt_ints[k] = old_pi
                elif c == j:
                    pt_ints[k] = old_pj

        if step >= burn_in:
            for ci in range(26):
                posterior_counts[ci][perm[ci]] += 1

    best_text = "".join(STANDARD_ALPHABET[p] for p in best_pt)

    # Compute MAP substitution from posterior
    map_perm = list(range(26))
    used: set[int] = set()
    # Greedy: assign most concentrated first
    entries = []
    for ci in range(26):
        best_pi = max(range(26), key=lambda pi: posterior_counts[ci][pi])
        conc = posterior_counts[ci][best_pi] / max(sum(posterior_counts[ci]), 1)
        entries.append((conc, ci, best_pi))
    entries.sort(reverse=True)
    assigned_cipher: set[int] = set()
    for _, ci, pi in entries:
        if ci in assigned_cipher or pi in used:
            continue
        map_perm[ci] = pi
        assigned_cipher.add(ci)
        used.add(pi)
    # Fill remaining
    remaining_pi = [i for i in range(26) if i not in used]
    remaining_ci = [i for i in range(26) if i not in assigned_cipher]
    for ci, pi in zip(remaining_ci, remaining_pi):
        map_perm[ci] = pi

    map_text = "".join(STANDARD_ALPHABET[map_perm[ord(c) - 65]] for c in ciphertext)
    map_ll = _bigram_log_likelihood(map_text)

    # Use best from sampling if better than posterior MAP
    if best_ll > map_ll:
        final_text = best_text
        final_perm = best_perm
        final_ll = best_ll
    else:
        final_text = map_text
        final_perm = map_perm
        final_ll = map_ll

    return {
        "posterior_counts": posterior_counts,
        "map_perm": final_perm,
        "map_text": final_text,
        "map_score": final_ll,
        "mode": "substitution",
    }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VIGENERE_PERIODS = list(range(2, 16))    # periods 2 through 15
GIBBS_STEPS = 200
GIBBS_TEMPERATURE = 1.0
NUM_SUBSTITUTION_CHAINS = 1


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    rng = random.Random(20250321)
    attempts = 0
    candidates: list[dict[str, object]] = []
    notes: list[str] = []
    period_analyses: list[dict[str, object]] = []

    # -----------------------------------------------------------------------
    # Phase 1: Vigenere Gibbs sampling across periods 2-20
    # -----------------------------------------------------------------------
    notes.append("Phase 1: Vigenere Gibbs sampling across periods 2-20")

    for period in VIGENERE_PERIODS:
        result = _gibbs_vigenere(
            K4, period, rng,
            num_steps=GIBBS_STEPS,
            temperature=GIBBS_TEMPERATURE,
        )
        attempts += 1

        analysis = _analyze_posterior(result)
        period_analyses.append(analysis)

        # Build candidate from MAP key
        map_key = str(result["map_key"])
        map_text = str(result["map_text"])
        map_score = float(result["map_score"])

        transform = f"bayesian_vigenere:period={period}:key={map_key}"
        key_mat = {
            "type": "bayesian_vigenere",
            "period": period,
            "key": map_key,
            "map_log_likelihood": round(map_score, 2),
            "avg_posterior_entropy": round(analysis["avg_entropy"], 3),
            "posterior_quality": analysis["quality"],
            "constraint_count": analysis["constraint_count"],
            "free_positions": analysis["free_positions"],
        }

        candidates.append(
            build_ranked_candidate(
                map_text,
                transform_chain=[transform],
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material=key_mat,
            )
        )

        # Report strong candidates
        if analysis["quality"] in ("strong", "moderate"):
            notes.append(
                f"  Period {period}: {analysis['quality']} "
                f"(avg_entropy={analysis['avg_entropy']:.2f}, "
                f"avg_conc={analysis['avg_concentration']:.2f}, "
                f"MAP key={analysis['map_key']}, "
                f"constraints={analysis['constraint_count']}/{period})"
            )

    # Summarize Vigenere results
    strong_periods = [a for a in period_analyses if a["quality"] == "strong"]
    moderate_periods = [a for a in period_analyses if a["quality"] == "moderate"]
    notes.append(f"Strong posterior concentration at {len(strong_periods)} period(s)")
    notes.append(f"Moderate posterior concentration at {len(moderate_periods)} period(s)")

    if strong_periods:
        best_strong = min(strong_periods, key=lambda a: a["avg_entropy"])
        notes.append(
            f"Best Vigenere period candidate: {best_strong['period']} "
            f"(entropy={best_strong['avg_entropy']:.3f})"
        )

    # -----------------------------------------------------------------------
    # Phase 2: Substitution cipher Gibbs sampling
    # -----------------------------------------------------------------------
    notes.append("Phase 2: Substitution cipher Gibbs sampling")

    for chain_idx in range(NUM_SUBSTITUTION_CHAINS):
        result = _gibbs_substitution(
            K4, rng,
            num_steps=GIBBS_STEPS,
            temperature=1.0 + chain_idx * 0.3,
        )
        attempts += 1

        map_text = str(result["map_text"])
        map_score = float(result["map_score"])
        map_perm = list(result["map_perm"])

        # Build the substitution alphabet string for reporting
        sub_alphabet = "".join(STANDARD_ALPHABET[p] for p in map_perm)

        transform = f"bayesian_substitution:chain={chain_idx}:alphabet={sub_alphabet}"
        key_mat = {
            "type": "bayesian_substitution",
            "chain": chain_idx,
            "substitution_alphabet": sub_alphabet,
            "map_log_likelihood": round(map_score, 2),
        }

        candidates.append(
            build_ranked_candidate(
                map_text,
                transform_chain=[transform],
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material=key_mat,
            )
        )

        notes.append(
            f"  Substitution chain {chain_idx}: "
            f"MAP log-likelihood={map_score:.2f}"
        )

    # -----------------------------------------------------------------------
    # Phase 3: Focused re-runs on top Vigenere periods
    # -----------------------------------------------------------------------
    notes.append("Phase 3: Focused re-runs on top Vigenere periods")

    # Select top 5 periods by posterior quality (lowest entropy)
    top_periods = sorted(period_analyses, key=lambda a: a["avg_entropy"])[:3]

    for analysis in top_periods:
        period = int(analysis["period"])

        # Run longer Gibbs chains with different temperatures
        for temp in (0.5, 1.5):
            result = _gibbs_vigenere(
                K4, period, rng,
                num_steps=GIBBS_STEPS * 2,  # 4000 steps for focused run
                temperature=temp,
            )
            attempts += 1

            map_key = str(result["map_key"])
            map_text = str(result["map_text"])
            map_score = float(result["map_score"])

            refined_analysis = _analyze_posterior(result)

            transform = f"bayesian_vigenere_focused:period={period}:temp={temp}:key={map_key}"
            key_mat = {
                "type": "bayesian_vigenere_focused",
                "period": period,
                "key": map_key,
                "temperature": temp,
                "map_log_likelihood": round(map_score, 2),
                "avg_posterior_entropy": round(refined_analysis["avg_entropy"], 3),
                "posterior_quality": refined_analysis["quality"],
            }

            candidates.append(
                build_ranked_candidate(
                    map_text,
                    transform_chain=[transform],
                    corpus_bundle=config.corpora,
                    scorer_profile=config.scorer_profile,
                    key_material=key_mat,
                )
            )

    # -----------------------------------------------------------------------
    # Phase 4: Posterior marginal analysis report
    # -----------------------------------------------------------------------
    notes.append("Phase 4: Posterior marginal analysis")

    # For the top 3 periods, report per-position posterior concentration
    for analysis in top_periods[:3]:
        period = int(analysis["period"])
        pos_report = []
        for pos in range(period):
            conc = analysis["position_concentrations"][pos]
            ent = analysis["position_entropies"][pos]
            letter = analysis["map_key"][pos]
            marker = "***" if conc > 0.5 else "**" if conc > 0.3 else "*" if conc > 0.2 else ""
            pos_report.append(f"{letter}({conc:.0%}){marker}")
        notes.append(f"  Period {period} marginals: [{', '.join(pos_report)}]")

    # -----------------------------------------------------------------------
    # Finalize
    # -----------------------------------------------------------------------
    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[:max(config.candidate_limit, 8)]

    notes.append(f"Total Gibbs sampling runs: {attempts}")
    notes.append(f"Unique candidates retained: {len(retained)}")

    return build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=notes,
    )
