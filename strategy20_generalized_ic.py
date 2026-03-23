"""Generalized IC and n-gram fingerprinting for K4 cipher identification.

Computes extended statistical fingerprints of K4 and compares them against
known cipher type profiles to identify the most likely cipher family:
  1. Standard IC, bigram IC, trigram IC
  2. IC at assumed periods 2-30
  3. Kappa test (mutual IC vs K1/K2/K3)
  4. Chi-squared vs English and uniform distributions
  5. Sliding-window IC profiles
  6. IC after hypothetical transposition inversions
  7. Shannon entropy and conditional entropy
"""

from __future__ import annotations

import math
from collections import Counter
from itertools import permutations
from statistics import mean

from kryptos.catalog import get_strategy_spec
from kryptos.common import (
    build_ranked_candidate,
    build_score_breakdown,
    build_strategy_result,
    calculate_ioc,
    dedupe_ranked_candidates,
    normalize_letters,
)
from kryptos.constants import (
    ANCHOR_COMPONENT_CLUES,
    K1_PT,
    K2_PT,
    K3_PT,
    K4,
    KRYPTOS_ALPHABET,
    STANDARD_ALPHABET,
)
from kryptos.runtime import StrategyRuntimeConfig
from kryptos.transposition import (
    identity_permutation,
    keyword_permutation,
    periodic_transposition_decrypt,
)

SPEC = get_strategy_spec("20")

# ---------------------------------------------------------------------------
# Known plaintext anchors (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# ---------------------------------------------------------------------------
# English letter frequencies (standard)
# ---------------------------------------------------------------------------
ENGLISH_FREQ: dict[str, float] = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074,
}

# Reference IC values for cipher family identification
IC_RANDOM = 1.0 / 26  # ~0.0385
IC_ENGLISH = 0.0667
IC_TRANSPOSITION = IC_ENGLISH  # transposition preserves letter frequencies
IC_MONOALPHABETIC = IC_ENGLISH

# Thematic keywords used for transposition permutation tests
THEME_KEYWORDS = ("KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN")


# ---------------------------------------------------------------------------
# Statistical helper functions
# ---------------------------------------------------------------------------
def ngram_ic(text: str, n: int) -> float:
    """Compute IC over n-grams (overlapping) of the given text."""
    normalized = normalize_letters(text)
    if len(normalized) < n + 1:
        return 0.0
    ngrams = [normalized[i:i + n] for i in range(len(normalized) - n + 1)]
    total = len(ngrams)
    if total <= 1:
        return 0.0
    counts = Counter(ngrams)
    return sum(c * (c - 1) for c in counts.values()) / (total * (total - 1))


def periodic_ic(text: str, period: int) -> float:
    """Split text into `period` columns and return mean IC of columns."""
    normalized = normalize_letters(text)
    if period <= 0 or period >= len(normalized):
        return 0.0
    columns = [normalized[i::period] for i in range(period)]
    column_ics = [calculate_ioc(col) for col in columns if len(col) > 1]
    return mean(column_ics) if column_ics else 0.0


def mutual_ic(text_a: str, text_b: str) -> float:
    """Kappa test: compute the mutual index of coincidence between two texts.

    Measures the probability that a random position has the same letter in both
    texts. For two independent random texts: ~1/26. For two English texts or
    texts enciphered with the same key: much higher.
    """
    a = normalize_letters(text_a)
    b = normalize_letters(text_b)
    min_len = min(len(a), len(b))
    if min_len == 0:
        return 0.0
    matches = sum(1 for i in range(min_len) if a[i] == b[i])
    return matches / min_len


def chi_squared_vs_english(text: str) -> float:
    """Chi-squared statistic comparing letter frequencies to English."""
    normalized = normalize_letters(text)
    n = len(normalized)
    if n == 0:
        return 0.0
    counts = Counter(normalized)
    chi2 = 0.0
    for letter in STANDARD_ALPHABET:
        observed = counts.get(letter, 0)
        expected = ENGLISH_FREQ[letter] * n
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


def chi_squared_vs_uniform(text: str) -> float:
    """Chi-squared statistic comparing letter frequencies to uniform."""
    normalized = normalize_letters(text)
    n = len(normalized)
    if n == 0:
        return 0.0
    counts = Counter(normalized)
    expected = n / 26.0
    return sum((counts.get(letter, 0) - expected) ** 2 / expected for letter in STANDARD_ALPHABET)


def sliding_window_ic(text: str, window_size: int) -> list[float]:
    """Compute IC on sliding windows of the given size across the text."""
    normalized = normalize_letters(text)
    if len(normalized) < window_size:
        return [calculate_ioc(normalized)] if len(normalized) > 1 else [0.0]
    return [
        calculate_ioc(normalized[i:i + window_size])
        for i in range(len(normalized) - window_size + 1)
    ]


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits) of the letter distribution."""
    normalized = normalize_letters(text)
    n = len(normalized)
    if n == 0:
        return 0.0
    counts = Counter(normalized)
    return -sum(
        (c / n) * math.log2(c / n)
        for c in counts.values()
        if c > 0
    )


def conditional_entropy(text: str) -> float:
    """First-order conditional entropy H(X_i | X_{i-1})."""
    normalized = normalize_letters(text)
    if len(normalized) < 2:
        return 0.0
    n = len(normalized)
    bigram_counts: Counter[str] = Counter()
    unigram_counts: Counter[str] = Counter()
    for i in range(n - 1):
        bigram_counts[normalized[i:i + 2]] += 1
        unigram_counts[normalized[i]] += 1
    total_bigrams = n - 1
    h = 0.0
    for bigram, count in bigram_counts.items():
        p_bigram = count / total_bigrams
        p_given = count / unigram_counts[bigram[0]]
        if p_given > 0:
            h -= p_bigram * math.log2(p_given)
    return h


def vigenere_expected_ic(period: int) -> float:
    """Expected IC for a Vigenère cipher with the given period."""
    return IC_RANDOM + (IC_ENGLISH - IC_RANDOM) / period


def check_anchor_match(text: str) -> int:
    """Count how many anchor characters match at known positions."""
    matches = 0
    for clue, start in ANCHORS:
        end = start + len(clue)
        if end <= len(text):
            matches += sum(1 for a, b in zip(text[start:end], clue) if a == b)
    return matches


# ---------------------------------------------------------------------------
# Main analysis and search
# ---------------------------------------------------------------------------
def run(config: StrategyRuntimeConfig | None = None) -> object:
    """Execute generalized IC fingerprinting analysis on K4."""
    candidates: list[dict[str, object]] = []
    notes: list[str] = []
    attempts = 0

    ct = normalize_letters(K4)
    n = len(ct)

    # -----------------------------------------------------------------------
    # 1. Standard IC
    # -----------------------------------------------------------------------
    ic_standard = calculate_ioc(ct)
    notes.append(f"Standard IC: {ic_standard:.6f} (English={IC_ENGLISH:.4f}, Random={IC_RANDOM:.4f})")

    # -----------------------------------------------------------------------
    # 2. Bigram IC
    # -----------------------------------------------------------------------
    ic_bigram = ngram_ic(ct, 2)
    notes.append(f"Bigram IC: {ic_bigram:.6f}")

    # -----------------------------------------------------------------------
    # 3. Trigram IC
    # -----------------------------------------------------------------------
    ic_trigram = ngram_ic(ct, 3)
    notes.append(f"Trigram IC: {ic_trigram:.6f}")

    # -----------------------------------------------------------------------
    # 4. Periodic IC for periods 2-30
    # -----------------------------------------------------------------------
    best_periodic_period = 0
    best_periodic_ic = 0.0
    periodic_results: list[str] = []
    for period in range(2, 31):
        pic = periodic_ic(ct, period)
        expected_vig = vigenere_expected_ic(period)
        periodic_results.append(f"  period={period}: IC={pic:.6f} (Vig expected={expected_vig:.4f})")
        if pic > best_periodic_ic:
            best_periodic_ic = pic
            best_periodic_period = period
    notes.append(f"Best periodic IC: period={best_periodic_period}, IC={best_periodic_ic:.6f}")
    # Report top 5 most interesting periods (closest to English IC)
    period_ics = [(p, periodic_ic(ct, p)) for p in range(2, 31)]
    period_ics.sort(key=lambda x: x[1], reverse=True)
    for p, pic in period_ics[:5]:
        notes.append(f"  Periodic IC peak: period={p}, IC={pic:.6f}")

    # -----------------------------------------------------------------------
    # 5. Kappa test: mutual IC with K1/K2/K3
    # -----------------------------------------------------------------------
    for label, solved_pt in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
        mic = mutual_ic(ct, normalize_letters(solved_pt))
        notes.append(f"Mutual IC (K4 vs {label}): {mic:.6f} (random={1/26:.4f})")
    # Also test shifted mutual IC
    for label, solved_pt in [("K1", K1_PT), ("K2", K2_PT), ("K3", K3_PT)]:
        solved = normalize_letters(solved_pt)
        best_shift_mic = 0.0
        best_shift = 0
        for shift in range(min(len(solved), 50)):
            mic = mutual_ic(ct, solved[shift:])
            if mic > best_shift_mic:
                best_shift_mic = mic
                best_shift = shift
        if best_shift_mic > 1.5 / 26:
            notes.append(f"  Best shifted mutual IC ({label}): shift={best_shift}, MIC={best_shift_mic:.6f}")

    # -----------------------------------------------------------------------
    # 6. Chi-squared tests
    # -----------------------------------------------------------------------
    chi2_eng = chi_squared_vs_english(ct)
    chi2_uni = chi_squared_vs_uniform(ct)
    notes.append(f"Chi-squared vs English: {chi2_eng:.2f} (lower = closer to English, df=25)")
    notes.append(f"Chi-squared vs Uniform: {chi2_uni:.2f} (lower = closer to random)")

    # -----------------------------------------------------------------------
    # 7. Sliding-window IC profiles
    # -----------------------------------------------------------------------
    for window_size in (10, 15, 20, 25):
        profile = sliding_window_ic(ct, window_size)
        if profile:
            avg = mean(profile)
            max_ic = max(profile)
            min_ic = min(profile)
            max_pos = profile.index(max_ic)
            notes.append(
                f"Sliding IC (w={window_size}): avg={avg:.5f}, "
                f"max={max_ic:.5f}@pos={max_pos}, min={min_ic:.5f}"
            )

    # -----------------------------------------------------------------------
    # 8. IC after hypothetical transposition inversions
    # -----------------------------------------------------------------------
    notes.append("--- Transposition inversion scan ---")
    transposition_hits: list[tuple[int, str, float, str]] = []  # (period, perm_label, ic, plaintext)

    for period in range(2, 31):
        attempts += 1
        # Identity permutation
        perm = identity_permutation(period)
        try:
            pt = periodic_transposition_decrypt(ct, period, perm)
            ic_after = calculate_ioc(pt)
            if ic_after > 0.050:  # Interesting: closer to English than raw K4
                transposition_hits.append((period, "identity", ic_after, pt))
        except Exception:
            pass

        # Keyword-derived permutations
        for kw in THEME_KEYWORDS:
            attempts += 1
            perm = keyword_permutation(kw, period)
            try:
                pt = periodic_transposition_decrypt(ct, period, perm)
                ic_after = calculate_ioc(pt)
                if ic_after > 0.050:
                    transposition_hits.append((period, f"kw:{kw}", ic_after, pt))
            except Exception:
                pass

        # Also try fill=column, read=row (reverse direction)
        for kw in THEME_KEYWORDS[:3]:
            attempts += 1
            perm = keyword_permutation(kw, period)
            try:
                pt = periodic_transposition_decrypt(
                    ct, period, perm,
                    fill_mode="column", read_mode="row",
                )
                ic_after = calculate_ioc(pt)
                if ic_after > 0.050:
                    transposition_hits.append((period, f"kw:{kw}:col-row", ic_after, pt))
            except Exception:
                pass

    # Sort by IC and report top hits
    transposition_hits.sort(key=lambda x: x[2], reverse=True)
    for period, perm_label, ic_after, pt in transposition_hits[:10]:
        anchor_matches = check_anchor_match(pt)
        notes.append(
            f"  Transposition p={period} [{perm_label}]: IC={ic_after:.6f}, "
            f"anchors={anchor_matches}"
        )
        # Generate candidates for the most promising
        if ic_after > 0.052 or anchor_matches > 2:
            attempts += 1
            candidate = build_ranked_candidate(
                pt,
                transform_chain=[f"transposition_inversion:p={period}:{perm_label}"],
                key_material={
                    "period": period,
                    "permutation_label": perm_label,
                    "ic_after_inversion": round(ic_after, 6),
                    "anchor_matches": anchor_matches,
                },
            )
            candidates.append(candidate)

    # -----------------------------------------------------------------------
    # 9. Entropy and conditional entropy
    # -----------------------------------------------------------------------
    h = shannon_entropy(ct)
    h_cond = conditional_entropy(ct)
    notes.append(f"Shannon entropy: {h:.4f} bits (uniform={math.log2(26):.4f})")
    notes.append(f"Conditional entropy H(X_i|X_{{i-1}}): {h_cond:.4f} bits")

    # -----------------------------------------------------------------------
    # Cipher family comparison
    # -----------------------------------------------------------------------
    notes.append("--- Cipher family IC comparison ---")
    families = {
        "Random": IC_RANDOM,
        "English/Mono/Transposition": IC_ENGLISH,
        "Bifid (typical)": (IC_RANDOM + IC_ENGLISH) / 2,
    }
    for p in (3, 5, 7, 10):
        families[f"Vigenere(p={p})"] = vigenere_expected_ic(p)
    for name, expected_ic in sorted(families.items(), key=lambda x: x[1]):
        delta = abs(ic_standard - expected_ic)
        indicator = " <-- CLOSE" if delta < 0.006 else ""
        notes.append(f"  {name}: expected={expected_ic:.5f}, delta={delta:.5f}{indicator}")

    # Determine best-matching family
    best_family = min(families.items(), key=lambda x: abs(ic_standard - x[1]))
    notes.append(f"Closest cipher family match: {best_family[0]} (IC={best_family[1]:.5f})")

    # If IC is close to English, note it could be transposition or monoalphabetic
    if abs(ic_standard - IC_ENGLISH) < 0.008:
        notes.append("NOTE: IC is close to English => possible transposition or monoalphabetic substitution")
    elif abs(ic_standard - IC_RANDOM) < 0.008:
        notes.append("NOTE: IC is close to random => possible polyalphabetic (Vigenere-like) cipher")
    else:
        notes.append("NOTE: IC is between random and English => possible fractionation, bifid, or polyalphabetic with short period")

    # -----------------------------------------------------------------------
    # Generate a fallback candidate from K4 raw if no transposition hits
    # -----------------------------------------------------------------------
    if not candidates:
        attempts += 1
        candidate = build_ranked_candidate(
            ct,
            transform_chain=["ic_fingerprint:baseline"],
            key_material={
                "ic_standard": round(ic_standard, 6),
                "ic_bigram": round(ic_bigram, 6),
                "ic_trigram": round(ic_trigram, 6),
                "entropy": round(h, 4),
                "chi2_english": round(chi2_eng, 2),
                "chi2_uniform": round(chi2_uni, 2),
                "best_periodic_period": best_periodic_period,
                "best_periodic_ic": round(best_periodic_ic, 6),
            },
        )
        candidates.append(candidate)

    candidates = dedupe_ranked_candidates(candidates)
    return build_strategy_result(SPEC, candidates, attempts=attempts, notes=notes)
