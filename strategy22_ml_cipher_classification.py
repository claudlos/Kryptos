"""ML-style cipher type classification for K4.

Extracts statistical features from K4 ciphertext and classifies it into
probability estimates for each major cipher family using a rule-based
decision-tree classifier built from published cipher type profiles.

For each cipher family with >10% probability, attempts a basic decryption
and scores the result against known plaintext anchors.
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

SPEC = get_strategy_spec("22")

# ---------------------------------------------------------------------------
# Known plaintext anchors (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# ---------------------------------------------------------------------------
# English letter frequencies (proportion, A-Z)
# ---------------------------------------------------------------------------
ENGLISH_FREQ = {
    "A": 0.08167, "B": 0.01492, "C": 0.02782, "D": 0.04253, "E": 0.12702,
    "F": 0.02228, "G": 0.02015, "H": 0.06094, "I": 0.06966, "J": 0.00153,
    "K": 0.00772, "L": 0.04025, "M": 0.02406, "N": 0.06749, "O": 0.07507,
    "P": 0.01929, "Q": 0.00095, "R": 0.05987, "S": 0.06327, "T": 0.09056,
    "U": 0.02758, "V": 0.00978, "W": 0.02360, "X": 0.00150, "Y": 0.01974,
    "Z": 0.00074,
}

# English IC for reference
ENGLISH_IC = 0.0667
RANDOM_IC = 1.0 / 26  # ~0.0385

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _letter_counts(text: str) -> dict[str, int]:
    """Count each letter in A-Z."""
    counts = {c: 0 for c in STANDARD_ALPHABET}
    for c in text:
        if c in counts:
            counts[c] += 1
    return counts


def _letter_frequencies(text: str) -> dict[str, float]:
    """Compute relative letter frequencies."""
    counts = _letter_counts(text)
    n = sum(counts.values())
    if n == 0:
        return {c: 0.0 for c in STANDARD_ALPHABET}
    return {c: counts[c] / n for c in STANDARD_ALPHABET}


def feature_ic(text: str) -> float:
    """Index of Coincidence."""
    return calculate_ioc(text)


def feature_max_periodic_ic(text: str, max_period: int = 30) -> tuple[float, int]:
    """Find maximum IC across periodic column extractions, return (max_ic, best_period)."""
    best_ic = 0.0
    best_period = 0
    n = len(text)
    for period in range(2, min(max_period + 1, n)):
        columns = [text[i::period] for i in range(period)]
        if not columns:
            continue
        avg_ic = sum(calculate_ioc(col) for col in columns) / len(columns)
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_period = period
    return best_ic, best_period


def feature_chi_squared_english(text: str) -> float:
    """Chi-squared distance from expected English letter frequencies."""
    freqs = _letter_frequencies(text)
    n = len(text)
    if n == 0:
        return 0.0
    chi_sq = 0.0
    for c in STANDARD_ALPHABET:
        expected = ENGLISH_FREQ[c] * n
        observed = freqs[c] * n
        if expected > 0:
            chi_sq += (observed - expected) ** 2 / expected
    return chi_sq


def feature_chi_squared_uniform(text: str) -> float:
    """Chi-squared distance from uniform distribution."""
    counts = _letter_counts(text)
    n = sum(counts.values())
    if n == 0:
        return 0.0
    expected = n / 26.0
    chi_sq = 0.0
    for c in STANDARD_ALPHABET:
        chi_sq += (counts[c] - expected) ** 2 / expected
    return chi_sq


def feature_repeated_bigrams_pct(text: str) -> float:
    """Percentage of bigrams that appear more than once."""
    if len(text) < 2:
        return 0.0
    bigrams: dict[str, int] = {}
    for i in range(len(text) - 1):
        bg = text[i:i + 2]
        bigrams[bg] = bigrams.get(bg, 0) + 1
    total = len(text) - 1
    repeated = sum(count for count in bigrams.values() if count > 1)
    return (repeated / total) * 100.0 if total > 0 else 0.0


def feature_entropy(text: str) -> float:
    """Shannon entropy in bits."""
    freqs = _letter_frequencies(text)
    entropy = 0.0
    for freq in freqs.values():
        if freq > 0:
            entropy -= freq * math.log2(freq)
    return entropy


def feature_has_j(text: str) -> bool:
    """Whether J appears in the ciphertext."""
    return "J" in text


def feature_longest_repeated_substring(text: str) -> int:
    """Length of the longest substring that appears at least twice."""
    n = len(text)
    best = 0
    # Use simple approach up to reasonable length
    for length in range(2, min(n // 2 + 1, 20)):
        seen: set[str] = set()
        found = False
        for i in range(n - length + 1):
            sub = text[i:i + length]
            if sub in seen:
                found = True
                best = length
                break
            seen.add(sub)
        if not found and length > best + 3:
            break  # early exit if no repeat for several lengths
    return best


def feature_even_odd_ic_ratio(text: str) -> float:
    """Ratio of IC at even positions to IC at odd positions."""
    even_chars = text[0::2]
    odd_chars = text[1::2]
    ic_even = calculate_ioc(even_chars) if len(even_chars) > 1 else 0.0
    ic_odd = calculate_ioc(odd_chars) if len(odd_chars) > 1 else 0.0
    if ic_odd == 0:
        return 1.0
    return ic_even / ic_odd


def feature_autocorrelation(text: str, max_lag: int = 30) -> list[tuple[int, float]]:
    """Autocorrelation at various lags: fraction of matching characters."""
    n = len(text)
    results = []
    for lag in range(1, min(max_lag + 1, n)):
        matches = sum(1 for i in range(n - lag) if text[i] == text[i + lag])
        correlation = matches / (n - lag) if (n - lag) > 0 else 0.0
        results.append((lag, correlation))
    return results


# ---------------------------------------------------------------------------
# Feature vector extraction
# ---------------------------------------------------------------------------

def extract_features(text: str) -> dict[str, object]:
    """Extract all classification features from text."""
    text = normalize_letters(text)
    ic = feature_ic(text)
    max_pic, best_period = feature_max_periodic_ic(text)
    chi_eng = feature_chi_squared_english(text)
    chi_uni = feature_chi_squared_uniform(text)
    bigram_pct = feature_repeated_bigrams_pct(text)
    entropy = feature_entropy(text)
    has_j = feature_has_j(text)
    lrs = feature_longest_repeated_substring(text)
    eo_ratio = feature_even_odd_ic_ratio(text)
    autocorr = feature_autocorrelation(text)

    # Find peak autocorrelation lag (excluding lag 0 effectively)
    peak_autocorr_lag = 0
    peak_autocorr_val = 0.0
    for lag, val in autocorr:
        if val > peak_autocorr_val:
            peak_autocorr_val = val
            peak_autocorr_lag = lag

    return {
        "ic": ic,
        "max_periodic_ic": max_pic,
        "best_periodic_ic_period": best_period,
        "chi_sq_english": chi_eng,
        "chi_sq_uniform": chi_uni,
        "repeated_bigram_pct": bigram_pct,
        "entropy": entropy,
        "has_j": has_j,
        "longest_repeated_substring": lrs,
        "even_odd_ic_ratio": eo_ratio,
        "peak_autocorr_lag": peak_autocorr_lag,
        "peak_autocorr_value": peak_autocorr_val,
        "autocorrelation": autocorr[:15],  # first 15 lags for reporting
    }


# ---------------------------------------------------------------------------
# Rule-based classifier
# ---------------------------------------------------------------------------

CIPHER_FAMILIES = [
    "monoalphabetic_substitution",
    "simple_transposition",
    "vigenere_short_period",
    "vigenere_long_period",
    "autokey",
    "playfair_or_bifid",
    "compound_cipher",
    "random_or_otp",
]


def classify_cipher(features: dict[str, object]) -> dict[str, float]:
    """Classify ciphertext into probability estimates for each cipher family.

    Uses a rule-based decision-tree classifier based on published cipher
    type statistical profiles (Friedman, Kasiski, Bauer).
    """
    ic = float(features["ic"])
    max_pic = float(features["max_periodic_ic"])
    best_period = int(features["best_periodic_ic_period"])
    chi_eng = float(features["chi_sq_english"])
    chi_uni = float(features["chi_sq_uniform"])
    bigram_pct = float(features["repeated_bigram_pct"])
    entropy = float(features["entropy"])
    has_j = bool(features["has_j"])
    lrs = int(features["longest_repeated_substring"])
    eo_ratio = float(features["even_odd_ic_ratio"])
    peak_autocorr = float(features["peak_autocorr_value"])

    # Initialize raw scores (log-odds style)
    scores: dict[str, float] = {family: 0.0 for family in CIPHER_FAMILIES}

    # --- Rule 1: IC level ---
    if ic > 0.060:
        # High IC => monoalphabetic or transposition (preserves English freqs)
        scores["monoalphabetic_substitution"] += 3.0
        scores["simple_transposition"] += 3.5
        scores["compound_cipher"] += 0.5
    elif 0.045 < ic <= 0.060:
        # Moderately depressed IC
        scores["vigenere_short_period"] += 2.0
        scores["autokey"] += 1.5
        scores["playfair_or_bifid"] += 1.5
        scores["compound_cipher"] += 1.0
    elif 0.038 <= ic <= 0.045:
        # IC near polyalphabetic with short period
        scores["vigenere_short_period"] += 2.5
        scores["vigenere_long_period"] += 1.5
        scores["autokey"] += 2.0
        scores["compound_cipher"] += 1.5
    else:
        # Very low IC
        scores["vigenere_long_period"] += 3.0
        scores["random_or_otp"] += 2.5
        scores["compound_cipher"] += 1.0

    # --- Rule 2: Periodic IC analysis ---
    if max_pic > 0.060:
        # Strong periodic IC signal => likely Vigenere with that period
        scores["vigenere_short_period"] += 3.0
        scores["monoalphabetic_substitution"] -= 1.0
    elif max_pic > 0.055:
        scores["vigenere_short_period"] += 2.0
        scores["vigenere_long_period"] += 0.5
    elif max_pic > 0.050:
        scores["vigenere_short_period"] += 1.0
        scores["autokey"] += 1.0
        scores["compound_cipher"] += 0.5
    else:
        # No strong periodic signal
        scores["vigenere_long_period"] += 1.0
        scores["random_or_otp"] += 1.0
        scores["compound_cipher"] += 1.0

    # --- Rule 3: Chi-squared from English ---
    if chi_eng < 30:
        # Close to English distribution => transposition or mono-substitution
        scores["simple_transposition"] += 3.0
        scores["monoalphabetic_substitution"] += 2.0
    elif chi_eng < 100:
        scores["simple_transposition"] += 1.5
        scores["vigenere_short_period"] += 0.5
        scores["compound_cipher"] += 1.0
    elif chi_eng < 300:
        scores["vigenere_short_period"] += 1.0
        scores["autokey"] += 1.0
        scores["playfair_or_bifid"] += 0.5
    else:
        scores["vigenere_long_period"] += 1.5
        scores["random_or_otp"] += 1.5

    # --- Rule 4: Chi-squared from uniform ---
    if chi_uni < 15:
        # Very close to uniform => polyalphabetic or random
        scores["vigenere_long_period"] += 2.0
        scores["random_or_otp"] += 2.0
        scores["monoalphabetic_substitution"] -= 2.0
        scores["simple_transposition"] -= 2.0
    elif chi_uni < 40:
        scores["vigenere_short_period"] += 1.0
        scores["autokey"] += 1.0
    else:
        scores["monoalphabetic_substitution"] += 1.5
        scores["simple_transposition"] += 1.5

    # --- Rule 5: Repeated bigrams ---
    if bigram_pct > 20:
        scores["monoalphabetic_substitution"] += 1.0
        scores["simple_transposition"] += 1.0
    elif bigram_pct > 10:
        scores["vigenere_short_period"] += 0.5
        scores["compound_cipher"] += 0.5
    else:
        scores["vigenere_long_period"] += 0.5
        scores["random_or_otp"] += 0.5

    # --- Rule 6: Entropy ---
    english_entropy = 4.18  # typical for English text
    max_entropy = math.log2(26)  # ~4.70 for uniform 26-letter
    if entropy > 4.5:
        scores["vigenere_long_period"] += 1.5
        scores["random_or_otp"] += 1.5
    elif entropy > 4.3:
        scores["vigenere_short_period"] += 1.0
        scores["autokey"] += 1.0
    else:
        scores["monoalphabetic_substitution"] += 1.0
        scores["simple_transposition"] += 1.0

    # --- Rule 7: Has J ---
    if not has_j:
        # Absence of J might indicate Polybius-based cipher (Playfair, Bifid)
        scores["playfair_or_bifid"] += 1.5
    else:
        scores["playfair_or_bifid"] -= 0.5

    # --- Rule 8: Longest repeated substring ---
    if lrs >= 4:
        scores["monoalphabetic_substitution"] += 1.0
        scores["simple_transposition"] += 0.5
        scores["vigenere_short_period"] += 0.5
    elif lrs >= 3:
        scores["vigenere_short_period"] += 0.5
    else:
        scores["random_or_otp"] += 1.0

    # --- Rule 9: Even/odd IC comparison ---
    if abs(eo_ratio - 1.0) > 0.3:
        # Significant asymmetry may indicate digraphic cipher or structured key
        scores["playfair_or_bifid"] += 1.5
        scores["compound_cipher"] += 1.0
    else:
        # Symmetric => consistent with standard polyalphabetic
        scores["vigenere_short_period"] += 0.5

    # --- Rule 10: Autocorrelation ---
    if peak_autocorr > 0.08:
        scores["vigenere_short_period"] += 1.5
        scores["simple_transposition"] += 0.5
    elif peak_autocorr > 0.055:
        scores["vigenere_short_period"] += 0.5
        scores["autokey"] += 0.5
    else:
        scores["vigenere_long_period"] += 0.5
        scores["random_or_otp"] += 0.5

    # Convert raw scores to probabilities via softmax
    max_score = max(scores.values())
    exp_scores = {k: math.exp(v - max_score) for k, v in scores.items()}
    total_exp = sum(exp_scores.values())
    probabilities = {k: v / total_exp for k, v in exp_scores.items()}

    return probabilities


# ---------------------------------------------------------------------------
# Decryption attempts for top families
# ---------------------------------------------------------------------------

def _attempt_caesar(ciphertext: str) -> list[dict[str, object]]:
    """Try all 26 Caesar shifts."""
    results = []
    for shift in range(26):
        key = STANDARD_ALPHABET[shift]
        plaintext = decrypt_vigenere_standard(ciphertext, key)
        results.append({
            "text": plaintext,
            "transform": f"caesar:shift={shift}",
            "key_material": {"type": "caesar", "shift": shift},
        })
    return results


def _attempt_vigenere_periods(ciphertext: str, periods: list[int]) -> list[dict[str, object]]:
    """Try Vigenere with frequency-analysis-derived keys at given periods."""
    results = []
    for period in periods:
        # Derive key by frequency analysis of each column
        key_chars = []
        for col in range(period):
            column = ciphertext[col::period]
            if not column:
                key_chars.append("A")
                continue
            counts = _letter_counts(column)
            # Most common letter in each column assumed to be 'E'
            best_shift = 0
            best_score = -1e9
            for shift in range(26):
                score = 0.0
                for c in STANDARD_ALPHABET:
                    decrypted_idx = (STANDARD_ALPHABET.index(c) - shift) % 26
                    decrypted_char = STANDARD_ALPHABET[decrypted_idx]
                    score += counts[c] * math.log(ENGLISH_FREQ[decrypted_char] + 1e-10)
                if score > best_score:
                    best_score = score
                    best_shift = shift
            key_chars.append(STANDARD_ALPHABET[best_shift])

        key = "".join(key_chars)
        plaintext = decrypt_vigenere_standard(ciphertext, key)
        results.append({
            "text": plaintext,
            "transform": f"vigenere:period={period}:key={key}",
            "key_material": {"type": "vigenere", "period": period, "key": key},
        })

    return results


def _attempt_reverse_transposition(ciphertext: str) -> list[dict[str, object]]:
    """Try simple columnar transposition reversals."""
    results = []
    n = len(ciphertext)
    for width in range(5, 15):
        if n < width:
            continue
        # Read off columns to reverse columnar transposition
        num_rows = math.ceil(n / width)
        # Number of full columns
        full_cols = n - width * (num_rows - 1) if num_rows > 1 else width
        if full_cols <= 0 or full_cols > width:
            full_cols = width

        # Reconstruct by reading columns
        grid: list[list[str]] = [[] for _ in range(width)]
        idx = 0
        for col in range(width):
            col_len = num_rows if col < full_cols else (num_rows - 1)
            for _ in range(col_len):
                if idx < n:
                    grid[col].append(ciphertext[idx])
                    idx += 1

        # Read row by row
        plaintext = []
        for row in range(num_rows):
            for col in range(width):
                if row < len(grid[col]):
                    plaintext.append(grid[col][row])
        text = "".join(plaintext)

        results.append({
            "text": text,
            "transform": f"columnar_transposition_reverse:width={width}",
            "key_material": {"type": "columnar_transposition", "width": width},
        })

    return results


def _attempt_affine(ciphertext: str) -> list[dict[str, object]]:
    """Try all valid affine cipher keys."""
    results = []
    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in valid_a:
        # Find modular inverse of a mod 26
        a_inv = pow(a, -1, 26)
        for b in range(26):
            plaintext = []
            for c in ciphertext:
                if c in STANDARD_ALPHABET:
                    y = STANDARD_ALPHABET.index(c)
                    x = (a_inv * (y - b)) % 26
                    plaintext.append(STANDARD_ALPHABET[x])
                else:
                    plaintext.append(c)
            text = "".join(plaintext)
            results.append({
                "text": text,
                "transform": f"affine:a={a}:b={b}",
                "key_material": {"type": "affine", "a": a, "b": b},
            })
    return results


# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------

def run(config: StrategyRuntimeConfig | None = None):
    config = config or StrategyRuntimeConfig()
    attempts = 0
    candidates: list[dict[str, object]] = []
    notes: list[str] = []

    # Step 1: Extract features
    text = normalize_letters(K4)
    features = extract_features(text)

    notes.append(f"K4 IC: {features['ic']:.4f}")
    notes.append(f"Max periodic IC: {features['max_periodic_ic']:.4f} at period {features['best_periodic_ic_period']}")
    notes.append(f"Chi-sq from English: {features['chi_sq_english']:.1f}")
    notes.append(f"Chi-sq from uniform: {features['chi_sq_uniform']:.1f}")
    notes.append(f"Repeated bigram %: {features['repeated_bigram_pct']:.1f}%")
    notes.append(f"Shannon entropy: {features['entropy']:.3f} bits")
    notes.append(f"Has J: {features['has_j']}")
    notes.append(f"Longest repeated substring: {features['longest_repeated_substring']}")
    notes.append(f"Even/odd IC ratio: {features['even_odd_ic_ratio']:.3f}")
    notes.append(f"Peak autocorrelation: {features['peak_autocorr_value']:.4f} at lag {features['peak_autocorr_lag']}")

    # Step 2: Classify
    probabilities = classify_cipher(features)

    sorted_families = sorted(probabilities.items(), key=lambda x: x[1], reverse=True)
    notes.append("--- Cipher family classification ---")
    for family, prob in sorted_families:
        notes.append(f"  {family}: {prob * 100:.1f}%")

    # Step 3: For each family with >10% probability, attempt decryption
    active_families = [(family, prob) for family, prob in sorted_families if prob > 0.10]
    notes.append(f"Active families (>10%): {[f[0] for f in active_families]}")

    for family, prob in active_families:
        family_results: list[dict[str, object]] = []

        if family == "monoalphabetic_substitution":
            # Try Caesar (a subset of monoalphabetic)
            family_results.extend(_attempt_caesar(K4))
            # Try affine (sample — limit to keep runtime reasonable)
            affine_results = _attempt_affine(K4)
            # Only keep top-scoring affine results
            scored_affine = []
            for r in affine_results:
                ic_val = calculate_ioc(r["text"])
                scored_affine.append((ic_val, r))
            scored_affine.sort(key=lambda x: x[0], reverse=True)
            family_results.extend([r for _, r in scored_affine[:20]])

        elif family == "simple_transposition":
            family_results.extend(_attempt_reverse_transposition(K4))

        elif family in ("vigenere_short_period", "vigenere_long_period"):
            if family == "vigenere_short_period":
                periods = list(range(2, 16))
            else:
                periods = list(range(14, 21))
            family_results.extend(_attempt_vigenere_periods(K4, periods))

            # Also try keys derived from periodic IC peak
            best_period = int(features["best_periodic_ic_period"])
            if best_period not in periods:
                family_results.extend(_attempt_vigenere_periods(K4, [best_period]))

        elif family == "autokey":
            # Try Vigenere with frequency-derived keys at various periods
            family_results.extend(_attempt_vigenere_periods(K4, list(range(3, 12))))

        elif family == "playfair_or_bifid":
            # Try Vigenere as proxy (Polybius decryption requires square search)
            family_results.extend(_attempt_vigenere_periods(K4, list(range(5, 11))))

        elif family == "compound_cipher":
            # Try Vigenere at various periods + transposition reversals
            family_results.extend(_attempt_vigenere_periods(K4, list(range(5, 13))))
            family_results.extend(_attempt_reverse_transposition(K4))

        elif family == "random_or_otp":
            # Nothing productive to try for true random; attempt Vigenere long periods
            family_results.extend(_attempt_vigenere_periods(K4, list(range(15, 21))))

        # Score and build candidates for this family
        for result in family_results:
            attempts += 1
            text_out = str(result["text"])
            transform = f"ml_classify:{family}:{result['transform']}"
            key_mat = dict(result.get("key_material", {}))
            key_mat["cipher_family"] = family
            key_mat["family_probability"] = round(prob, 4)

            candidates.append(
                build_ranked_candidate(
                    text_out,
                    transform_chain=[transform],
                    corpus_bundle=config.corpora,
                    scorer_profile=config.scorer_profile,
                    key_material=key_mat,
                )
            )

    # Dedupe and rank
    ranked = dedupe_ranked_candidates(candidates)
    retained = ranked[:max(config.candidate_limit, 8)]

    notes.append(f"Total decryption attempts: {attempts}")
    notes.append(f"Unique candidates retained: {len(retained)}")

    return build_strategy_result(
        SPEC,
        retained,
        attempts=attempts,
        notes=notes,
    )
