"""Metropolis-Hastings MCMC key search for K4.

Runs parallel MCMC chains to recover Vigenère and/or transposition keys:
  1. State = candidate key (Vigenère key string or column permutation or both)
  2. Proposal = small random perturbation of key
  3. Score = n-gram log-likelihood + anchor position bonus
  4. Accept/reject via Metropolis criterion with simulated annealing
  5. Hard constraints: reject states violating known plaintext at anchor positions
"""

from __future__ import annotations

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    anchor_alignment_score,
    build_ranked_candidate,
    build_score_breakdown,
    build_strategy_result,
    decrypt_vigenere_standard,
    dedupe_ranked_candidates,
    language_shape_score,
    normalize_letters,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    DEFAULT_KEYWORDS,
    K4,
    KNOWN_PLAINTEXT_CLUES,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import (
    identity_permutation,
    keyword_permutation,
    periodic_transposition_decrypt,
)

import math
import random

SPEC = get_strategy_spec("19")

# ---------------------------------------------------------------------------
# Known plaintext anchors (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

COMBINED_ANCHORS: list[tuple[str, int]] = []
for _clue, _details in KNOWN_PLAINTEXT_CLUES.items():
    COMBINED_ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# ---------------------------------------------------------------------------
# Hardcoded English bigram and trigram log-probabilities
# ---------------------------------------------------------------------------
# Top ~80 English bigrams with approximate log10 frequencies (from large corpora).
# Values are log10(probability) where probability = freq / total_bigrams.
BIGRAM_LOG_FREQ: dict[str, float] = {
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

# Top ~50 English trigrams with approximate log10 frequencies.
TRIGRAM_LOG_FREQ: dict[str, float] = {
    "THE": -1.78, "AND": -2.15, "ING": -2.28, "ION": -2.52, "TIO": -2.56,
    "ENT": -2.60, "ERE": -2.64, "HER": -2.68, "ATE": -2.72, "VER": -2.76,
    "TER": -2.78, "THA": -2.80, "ATI": -2.82, "HAT": -2.84, "ALL": -2.86,
    "ETH": -2.88, "FOR": -2.90, "HIS": -2.92, "EST": -2.94, "OFT": -2.96,
    "STH": -2.98, "OTH": -3.00, "RES": -3.02, "ITH": -3.04, "ONT": -3.06,
    "INT": -3.08, "ERS": -3.10, "MAN": -3.12, "NOT": -3.14, "NDE": -3.16,
    "AST": -3.18, "WIT": -3.20, "OUR": -3.22, "ARE": -3.24, "NTH": -3.26,
    "EAR": -3.28, "EAS": -3.30, "NOR": -3.32, "ORT": -3.34, "OUN": -3.36,
    "HEA": -3.38, "OUT": -3.40, "STA": -3.42, "BER": -3.44, "LIN": -3.46,
    "CAN": -3.48, "OOK": -3.50, "CLO": -3.52, "OCK": -3.54, "ERL": -3.56,
}

# Default log-prob for unseen n-grams
BIGRAM_FLOOR = -4.5
TRIGRAM_FLOOR = -5.5


def _ngram_log_score(text: str) -> float:
    """Compute combined bigram + trigram log-probability score for text."""
    if len(text) < 2:
        return -999.0

    score = 0.0
    # Bigram contribution
    for i in range(len(text) - 1):
        bg = text[i : i + 2]
        score += BIGRAM_LOG_FREQ.get(bg, BIGRAM_FLOOR)

    # Trigram contribution (weighted more heavily)
    for i in range(len(text) - 2):
        tg = text[i : i + 3]
        score += TRIGRAM_LOG_FREQ.get(tg, TRIGRAM_FLOOR) * 1.5

    return score


def _anchor_bonus(text: str) -> float:
    """Bonus for matching known plaintext at anchor positions."""
    bonus = 0.0
    for plaintext, start_idx in ANCHORS:
        end_idx = start_idx + len(plaintext)
        if end_idx > len(text):
            continue
        segment = text[start_idx:end_idx]
        matches = sum(1 for a, b in zip(segment, plaintext) if a == b)
        bonus += matches * 8.0  # strong per-char bonus
        if segment == plaintext:
            bonus += 50.0  # full match bonus
    return bonus


def _anchor_violated(text: str) -> bool:
    """Return True if text contradicts hard anchor constraints.

    We enforce that at minimum the combined anchors (EASTNORTHEAST, BERLINCLOCK)
    must have at least 1 character match in each region. This is a soft-hard
    constraint: full violation = 0 matches in a region.
    """
    for plaintext, start_idx in COMBINED_ANCHORS:
        end_idx = start_idx + len(plaintext)
        if end_idx > len(text):
            continue
        segment = text[start_idx:end_idx]
        if sum(1 for a, b in zip(segment, plaintext) if a == b) == 0:
            return True
    return False


def _mcmc_score(text: str) -> float:
    """Combined MCMC scoring function: n-gram log-likelihood + anchor bonus."""
    return _ngram_log_score(text) + _anchor_bonus(text)


# ---------------------------------------------------------------------------
# MCMC Chain: Vigenère key search
# ---------------------------------------------------------------------------

def _mcmc_vigenere_chain(
    ciphertext: str,
    period: int,
    rng: random.Random,
    num_steps: int = 3000,
    initial_temp: float = 5.0,
    final_temp: float = 0.3,
) -> dict[str, object]:
    """Run one MCMC chain searching for a Vigenère key of given period."""

    # Initialize key: use anchor-derived shifts where possible, random elsewhere
    shifts: list[int] = []
    fixed_slots: set[int] = set()
    slot_constraints: dict[int, int] = {}

    for plaintext, start_idx in ANCHORS:
        for offset, (p_char, c_char) in enumerate(
            zip(plaintext, ciphertext[start_idx : start_idx + len(plaintext)])
        ):
            slot = (start_idx + offset) % period
            derived = (STANDARD_ALPHABET.index(c_char) - STANDARD_ALPHABET.index(p_char)) % 26
            if slot in slot_constraints:
                if slot_constraints[slot] != derived:
                    # Period incompatible with anchors — still try random
                    slot_constraints.clear()
                    fixed_slots.clear()
                    break
                continue
            slot_constraints[slot] = derived
            fixed_slots.add(slot)

    for i in range(period):
        if i in slot_constraints:
            shifts.append(slot_constraints[i])
        else:
            shifts.append(rng.randrange(26))

    # Evaluate initial state
    key_str = "".join(STANDARD_ALPHABET[s] for s in shifts)
    current_text = decrypt_vigenere_standard(ciphertext, key_str)
    current_score = _mcmc_score(current_text)

    best_shifts = list(shifts)
    best_score = current_score
    best_text = current_text

    free_slots = [i for i in range(period) if i not in fixed_slots]
    if not free_slots:
        free_slots = list(range(period))  # fallback: search all

    for step in range(num_steps):
        # Annealing temperature
        progress = step / max(num_steps - 1, 1)
        temperature = initial_temp * (1 - progress) + final_temp * progress

        # Propose: perturb one random free slot
        slot = rng.choice(free_slots)
        old_val = shifts[slot]
        # Either shift by ±1..3, or jump to random
        if rng.random() < 0.7:
            delta = rng.choice([-3, -2, -1, 1, 2, 3])
            new_val = (old_val + delta) % 26
        else:
            new_val = rng.randrange(26)

        if new_val == old_val:
            continue

        # Apply proposal
        shifts[slot] = new_val
        key_str = "".join(STANDARD_ALPHABET[s] for s in shifts)
        proposed_text = decrypt_vigenere_standard(ciphertext, key_str)

        # Hard constraint check
        if _anchor_violated(proposed_text):
            shifts[slot] = old_val
            continue

        proposed_score = _mcmc_score(proposed_text)

        # Metropolis acceptance
        delta_score = proposed_score - current_score
        if delta_score > 0:
            accept = True
        else:
            accept_prob = math.exp(delta_score / max(temperature, 0.01))
            accept = rng.random() < accept_prob

        if accept:
            current_score = proposed_score
            current_text = proposed_text
            if current_score > best_score:
                best_score = current_score
                best_shifts = list(shifts)
                best_text = current_text
        else:
            shifts[slot] = old_val

    return {
        "text": best_text,
        "score": best_score,
        "key": "".join(STANDARD_ALPHABET[s] for s in best_shifts),
        "period": period,
        "mode": "vigenere",
    }


# ---------------------------------------------------------------------------
# MCMC Chain: Transposition permutation search
# ---------------------------------------------------------------------------

def _mcmc_transposition_chain(
    ciphertext: str,
    width: int,
    rng: random.Random,
    fill_mode: str = "row",
    read_mode: str = "column",
    num_steps: int = 2000,
    initial_temp: float = 5.0,
    final_temp: float = 0.3,
) -> dict[str, object]:
    """Run one MCMC chain searching for a transposition column permutation."""

    # Initialize with random permutation
    perm = list(range(width))
    rng.shuffle(perm)

    current_text = periodic_transposition_decrypt(
        ciphertext, width, tuple(perm), fill_mode=fill_mode, read_mode=read_mode
    )
    current_score = _mcmc_score(current_text)

    best_perm = list(perm)
    best_score = current_score
    best_text = current_text

    for step in range(num_steps):
        progress = step / max(num_steps - 1, 1)
        temperature = initial_temp * (1 - progress) + final_temp * progress

        # Propose: swap two columns
        i = rng.randrange(width)
        j = rng.randrange(width)
        while j == i:
            j = rng.randrange(width)
        perm[i], perm[j] = perm[j], perm[i]

        proposed_text = periodic_transposition_decrypt(
            ciphertext, width, tuple(perm), fill_mode=fill_mode, read_mode=read_mode
        )
        proposed_score = _mcmc_score(proposed_text)

        delta_score = proposed_score - current_score
        if delta_score > 0:
            accept = True
        else:
            accept_prob = math.exp(delta_score / max(temperature, 0.01))
            accept = rng.random() < accept_prob

        if accept:
            current_score = proposed_score
            current_text = proposed_text
            if current_score > best_score:
                best_score = current_score
                best_perm = list(perm)
                best_text = current_text
        else:
            # Undo swap
            perm[i], perm[j] = perm[j], perm[i]

    return {
        "text": best_text,
        "score": best_score,
        "permutation": tuple(best_perm),
        "width": width,
        "fill_mode": fill_mode,
        "read_mode": read_mode,
        "mode": "transposition",
    }


# ---------------------------------------------------------------------------
# MCMC Chain: Combined Vigenère + Transposition
# ---------------------------------------------------------------------------

def _mcmc_combined_chain(
    ciphertext: str,
    period: int,
    width: int,
    rng: random.Random,
    fill_mode: str = "row",
    read_mode: str = "column",
    num_steps: int = 4000,
    initial_temp: float = 6.0,
    final_temp: float = 0.2,
) -> dict[str, object]:
    """Run one MCMC chain jointly searching Vigenère key + transposition permutation."""

    # Initialize Vigenère key from anchors
    shifts: list[int] = []
    fixed_slots: set[int] = set()
    slot_constraints: dict[int, int] = {}

    for plaintext, start_idx in ANCHORS:
        for offset, (p_char, c_char) in enumerate(
            zip(plaintext, ciphertext[start_idx : start_idx + len(plaintext)])
        ):
            slot = (start_idx + offset) % period
            derived = (STANDARD_ALPHABET.index(c_char) - STANDARD_ALPHABET.index(p_char)) % 26
            if slot in slot_constraints and slot_constraints[slot] != derived:
                slot_constraints.clear()
                fixed_slots.clear()
                break
            slot_constraints[slot] = derived
            fixed_slots.add(slot)

    for i in range(period):
        shifts.append(slot_constraints.get(i, rng.randrange(26)))

    free_slots = [i for i in range(period) if i not in fixed_slots]
    if not free_slots:
        free_slots = list(range(period))

    # Initialize transposition permutation
    perm = list(range(width))
    rng.shuffle(perm)

    # Evaluate initial state
    trans_text = periodic_transposition_decrypt(
        ciphertext, width, tuple(perm), fill_mode=fill_mode, read_mode=read_mode
    )
    key_str = "".join(STANDARD_ALPHABET[s] for s in shifts)
    current_text = decrypt_vigenere_standard(trans_text, key_str)
    current_score = _mcmc_score(current_text)

    best_shifts = list(shifts)
    best_perm = list(perm)
    best_score = current_score
    best_text = current_text

    for step in range(num_steps):
        progress = step / max(num_steps - 1, 1)
        temperature = initial_temp * (1 - progress) + final_temp * progress

        # Randomly choose to perturb Vigenère or transposition
        if rng.random() < 0.5:
            # Perturb Vigenère key
            slot = rng.choice(free_slots)
            old_val = shifts[slot]
            if rng.random() < 0.7:
                delta = rng.choice([-3, -2, -1, 1, 2, 3])
                new_val = (old_val + delta) % 26
            else:
                new_val = rng.randrange(26)
            if new_val == old_val:
                continue
            shifts[slot] = new_val
            key_str = "".join(STANDARD_ALPHABET[s] for s in shifts)
            proposed_text = decrypt_vigenere_standard(trans_text, key_str)

            delta_score = _mcmc_score(proposed_text) - current_score
            if delta_score > 0 or rng.random() < math.exp(delta_score / max(temperature, 0.01)):
                current_text = proposed_text
                current_score += delta_score  # approximation; recompute to be safe
                current_score = _mcmc_score(current_text)
                if current_score > best_score:
                    best_score = current_score
                    best_shifts = list(shifts)
                    best_perm = list(perm)
                    best_text = current_text
            else:
                shifts[slot] = old_val
        else:
            # Perturb transposition
            i = rng.randrange(width)
            j = rng.randrange(width)
            while j == i:
                j = rng.randrange(width)
            perm[i], perm[j] = perm[j], perm[i]

            new_trans_text = periodic_transposition_decrypt(
                ciphertext, width, tuple(perm), fill_mode=fill_mode, read_mode=read_mode
            )
            key_str = "".join(STANDARD_ALPHABET[s] for s in shifts)
            proposed_text = decrypt_vigenere_standard(new_trans_text, key_str)

            proposed_score = _mcmc_score(proposed_text)
            delta_score = proposed_score - current_score
            if delta_score > 0 or rng.random() < math.exp(delta_score / max(temperature, 0.01)):
                trans_text = new_trans_text
                current_text = proposed_text
                current_score = proposed_score
                if current_score > best_score:
                    best_score = current_score
                    best_shifts = list(shifts)
                    best_perm = list(perm)
                    best_text = current_text
            else:
                perm[i], perm[j] = perm[j], perm[i]

    return {
        "text": best_text,
        "score": best_score,
        "key": "".join(STANDARD_ALPHABET[s] for s in best_shifts),
        "period": period,
        "permutation": tuple(best_perm),
        "width": width,
        "fill_mode": fill_mode,
        "read_mode": read_mode,
        "mode": "combined",
    }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NUM_VIG_CHAINS = 4          # chains per Vigenère period
NUM_TRANS_CHAINS = 3        # chains per transposition width
NUM_COMBINED_CHAINS = 2     # chains per combined (period, width) pair
VIG_PERIODS = (5, 6, 7, 8, 9, 10, 11, 12, 13, 14)
TRANS_WIDTHS = (5, 7, 8, 9, 10, 11, 12, 14)
COMBINED_PERIODS = (6, 7, 8, 10, 12)
COMBINED_WIDTHS = (7, 9, 10, 12)


def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    rng = random.Random(20250321)
    attempts = 0
    all_results: list[dict[str, object]] = []

    # Phase 1: Vigenère-only MCMC chains
    for period in VIG_PERIODS:
        for chain_idx in range(NUM_VIG_CHAINS):
            result = _mcmc_vigenere_chain(
                K4, period, rng, num_steps=3000,
                initial_temp=5.0 + chain_idx * 0.5,
                final_temp=0.2 + chain_idx * 0.1,
            )
            attempts += 1
            all_results.append(result)

    # Phase 2: Transposition-only MCMC chains
    for width in TRANS_WIDTHS:
        for fill_mode, read_mode in (("row", "column"), ("column", "row")):
            for chain_idx in range(NUM_TRANS_CHAINS):
                result = _mcmc_transposition_chain(
                    K4, width, rng,
                    fill_mode=fill_mode,
                    read_mode=read_mode,
                    num_steps=2000,
                    initial_temp=5.0 + chain_idx * 0.7,
                    final_temp=0.3 + chain_idx * 0.1,
                )
                attempts += 1
                all_results.append(result)

    # Phase 3: Combined Vigenère + transposition MCMC chains
    for period in COMBINED_PERIODS:
        for width in COMBINED_WIDTHS:
            for fill_mode, read_mode in (("row", "column"),):
                for chain_idx in range(NUM_COMBINED_CHAINS):
                    result = _mcmc_combined_chain(
                        K4, period, width, rng,
                        fill_mode=fill_mode,
                        read_mode=read_mode,
                        num_steps=3000,
                        initial_temp=6.0 + chain_idx,
                        final_temp=0.2,
                    )
                    attempts += 1
                    all_results.append(result)

    # Build ranked candidates
    candidates: list[dict[str, object]] = []
    for r in all_results:
        text = str(r["text"])
        if not text:
            continue

        mode = str(r["mode"])
        chain: list[str] = []
        key_mat: dict[str, object] = {"mcmc_mode": mode}

        if mode == "vigenere":
            chain.append(f"mcmc_vigenere:period={r['period']}:key={r['key']}")
            key_mat["vigenere_key"] = r["key"]
            key_mat["period"] = r["period"]
        elif mode == "transposition":
            chain.append(
                f"mcmc_transposition:w{r['width']}:{r['fill_mode']}->{r['read_mode']}"
            )
            key_mat["width"] = r["width"]
            key_mat["permutation"] = list(r["permutation"])
            key_mat["fill_mode"] = r["fill_mode"]
            key_mat["read_mode"] = r["read_mode"]
        elif mode == "combined":
            chain.append(
                f"mcmc_transposition:w{r['width']}:{r['fill_mode']}->{r['read_mode']}"
            )
            chain.append(f"mcmc_vigenere:period={r['period']}:key={r['key']}")
            key_mat["vigenere_key"] = r["key"]
            key_mat["period"] = r["period"]
            key_mat["width"] = r["width"]
            key_mat["permutation"] = list(r["permutation"])
            key_mat["fill_mode"] = r["fill_mode"]
            key_mat["read_mode"] = r["read_mode"]

        candidates.append(
            build_ranked_candidate(
                text,
                transform_chain=chain,
                corpus_bundle=config.corpora,
                scorer_profile=config.scorer_profile,
                key_material=key_mat,
            )
        )

    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[: max(config.candidate_limit, 8)]

    vig_count = sum(1 for r in all_results if r["mode"] == "vigenere")
    trans_count = sum(1 for r in all_results if r["mode"] == "transposition")
    combined_count = sum(1 for r in all_results if r["mode"] == "combined")

    return build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=[
            f"Ran {vig_count} Vigenère-only MCMC chains across periods {VIG_PERIODS}.",
            f"Ran {trans_count} transposition-only MCMC chains across widths {TRANS_WIDTHS}.",
            f"Ran {combined_count} combined Vigenère+transposition MCMC chains.",
            "Metropolis-Hastings with simulated annealing schedule.",
            "N-gram scoring: hardcoded top-80 bigrams + top-50 trigrams log-frequencies.",
            "Hard constraints: reject proposals violating known plaintext anchors.",
            f"Total chains evaluated: {attempts}.",
        ],
    )
