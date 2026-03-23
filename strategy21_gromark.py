"""Gromark cipher investigation for K4.

The Gromark cipher uses a running numerical key where each new key digit is
the sum (mod 10) of two previous digits (Fibonacci-like). It was used by
military intelligence and is documented in Friedman's Military Cryptanalysis
texts, which Ed Scheidt cited as relevant to Kryptos.

Search strategy:
  1. All 2-digit primers (00-99)
  2. All 3-digit primers (000-999)
  3. All 4-digit primers (0000-9999)
  4. Optional 5-digit primers from keyword-derived seeds
  5. Both standard and KRYPTOS-keyed alphabets
"""

from __future__ import annotations

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

SPEC = get_strategy_spec("21")

# ---------------------------------------------------------------------------
# Known plaintext anchors (0-indexed)
# ---------------------------------------------------------------------------
ANCHORS: list[tuple[str, int]] = []
for _clue, _details in ANCHOR_COMPONENT_CLUES.items():
    ANCHORS.append((_clue, int(_details["start_index"]) - 1))

# Keyword seeds for 5-digit primer generation
KEYWORD_SEEDS = ("KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN")


# ---------------------------------------------------------------------------
# Gromark cipher implementation
# ---------------------------------------------------------------------------
def generate_gromark_key(primer: list[int], length: int) -> list[int]:
    """Generate a Gromark running key from a numeric primer.

    Each subsequent key digit is (key[i-1] + key[i-2]) mod 10, producing a
    Fibonacci-like sequence modulo 10.
    """
    if len(primer) < 2:
        raise ValueError("Gromark primer must have at least 2 digits")
    key = list(primer)
    while len(key) < length:
        key.append((key[-1] + key[-2]) % 10)
    return key[:length]


def gromark_decrypt(ciphertext: str, primer: list[int], alphabet: str = STANDARD_ALPHABET) -> str:
    """Decrypt ciphertext using the Gromark cipher.

    For each position: plaintext[i] = alphabet[(alphabet.index(ct[i]) - key[i]) mod 26]
    """
    ct = normalize_letters(ciphertext)
    n = len(ct)
    key = generate_gromark_key(primer, n)
    plaintext: list[str] = []
    for i in range(n):
        if ct[i] not in alphabet:
            plaintext.append(ct[i])
            continue
        ct_idx = alphabet.index(ct[i])
        pt_idx = (ct_idx - key[i]) % 26
        plaintext.append(alphabet[pt_idx])
    return "".join(plaintext)


def gromark_encrypt(plaintext: str, primer: list[int], alphabet: str = STANDARD_ALPHABET) -> str:
    """Encrypt plaintext using the Gromark cipher (for verification)."""
    pt = normalize_letters(plaintext)
    n = len(pt)
    key = generate_gromark_key(primer, n)
    ciphertext: list[str] = []
    for i in range(n):
        if pt[i] not in alphabet:
            ciphertext.append(pt[i])
            continue
        pt_idx = alphabet.index(pt[i])
        ct_idx = (pt_idx + key[i]) % 26
        ciphertext.append(alphabet[ct_idx])
    return "".join(ciphertext)


def check_anchor_matches(text: str) -> tuple[int, int]:
    """Return (total_char_matches, full_anchor_matches) at known positions."""
    char_matches = 0
    full_matches = 0
    for clue, start in ANCHORS:
        end = start + len(clue)
        if end <= len(text):
            segment = text[start:end]
            matches = sum(1 for a, b in zip(segment, clue) if a == b)
            char_matches += matches
            if matches == len(clue):
                full_matches += 1
    return char_matches, full_matches


def quick_anchor_check(text: str, threshold: int = 3) -> bool:
    """Fast anchor check: return True if at least `threshold` chars match."""
    matches = 0
    for clue, start in ANCHORS:
        end = start + len(clue)
        if end <= len(text):
            for a, b in zip(text[start:end], clue):
                if a == b:
                    matches += 1
                    if matches >= threshold:
                        return True
    return False


def keyword_to_digits(keyword: str) -> list[int]:
    """Convert a keyword to a list of digits via character positions mod 10."""
    return [ord(c) % 10 for c in normalize_letters(keyword)]


def score_candidate(text: str) -> int:
    """Quick score: anchor char matches * 100 + IC bonus."""
    char_matches, full_matches = check_anchor_matches(text)
    ic = calculate_ioc(text)
    ic_bonus = int(max(0, (ic - 0.04)) * 2000)
    return char_matches * 100 + full_matches * 500 + ic_bonus


# ---------------------------------------------------------------------------
# Main search
# ---------------------------------------------------------------------------
def run(config: StrategyRuntimeConfig | None = None) -> object:
    """Execute Gromark cipher search on K4."""
    candidates: list[dict[str, object]] = []
    notes: list[str] = []
    attempts = 0
    ct = normalize_letters(K4)

    # Track best results across all searches
    best_score = 0
    best_results: list[tuple[int, list[int], str, str, int, int]] = []  # (score, primer, alphabet_name, text, chars, fulls)

    # The alphabets to try
    alphabets = [
        ("standard", STANDARD_ALPHABET),
        ("kryptos", KRYPTOS_ALPHABET),
    ]

    def process_primer(primer: list[int], alphabet_name: str, alphabet: str) -> None:
        nonlocal attempts, best_score
        attempts += 1
        pt = gromark_decrypt(ct, primer, alphabet)

        # Quick filter: check if at least 3 anchor chars match
        if not quick_anchor_check(pt, threshold=3):
            return

        char_matches, full_matches = check_anchor_matches(pt)
        score = score_candidate(pt)

        if score > best_score - 200 or char_matches >= 5 or full_matches >= 1:
            best_results.append((score, primer, alphabet_name, pt, char_matches, full_matches))
            if score > best_score:
                best_score = score

    # -------------------------------------------------------------------
    # Phase 1: 2-digit primers (100 combinations per alphabet)
    # -------------------------------------------------------------------
    notes.append("Phase 1: 2-digit primers (00-99)")
    for alphabet_name, alphabet in alphabets:
        for d0 in range(10):
            for d1 in range(10):
                process_primer([d0, d1], alphabet_name, alphabet)
    notes.append(f"  2-digit: {attempts} attempts, best_score={best_score}")

    # -------------------------------------------------------------------
    # Phase 2: 3-digit primers (1000 combinations per alphabet)
    # -------------------------------------------------------------------
    phase2_start = attempts
    notes.append("Phase 2: 3-digit primers (000-999)")
    for alphabet_name, alphabet in alphabets:
        for d0 in range(10):
            for d1 in range(10):
                for d2 in range(10):
                    process_primer([d0, d1, d2], alphabet_name, alphabet)
    notes.append(f"  3-digit: {attempts - phase2_start} attempts, best_score={best_score}")

    # -------------------------------------------------------------------
    # Phase 3: 4-digit primers (10000 combinations per alphabet)
    # -------------------------------------------------------------------
    phase3_start = attempts
    notes.append("Phase 3: 4-digit primers (0000-9999)")
    for alphabet_name, alphabet in alphabets:
        for d0 in range(10):
            for d1 in range(10):
                for d2 in range(10):
                    for d3 in range(10):
                        process_primer([d0, d1, d2, d3], alphabet_name, alphabet)
    notes.append(f"  4-digit: {attempts - phase3_start} attempts, best_score={best_score}")

    # -------------------------------------------------------------------
    # Phase 4: 5-digit primers from keyword-derived seeds
    # -------------------------------------------------------------------
    phase4_start = attempts
    notes.append("Phase 4: 5-digit keyword-derived primers")
    seen_primers: set[tuple[int, ...]] = set()
    for kw in KEYWORD_SEEDS:
        digits = keyword_to_digits(kw)
        # Use first 5 digits and variations
        if len(digits) >= 5:
            for start in range(min(len(digits) - 4, 5)):
                primer_5 = digits[start:start + 5]
                primer_key = tuple(primer_5)
                if primer_key in seen_primers:
                    continue
                seen_primers.add(primer_key)
                for alphabet_name, alphabet in alphabets:
                    process_primer(primer_5, alphabet_name, alphabet)
        # Also try first 2,3,4 digits of keyword
        for length in range(2, min(len(digits) + 1, 6)):
            primer_kw = digits[:length]
            primer_key = tuple(primer_kw)
            if primer_key in seen_primers:
                continue
            seen_primers.add(primer_key)
            for alphabet_name, alphabet in alphabets:
                process_primer(primer_kw, alphabet_name, alphabet)
    notes.append(f"  5-digit keyword: {attempts - phase4_start} attempts, best_score={best_score}")

    # -------------------------------------------------------------------
    # Phase 5: Try Gromark with primer derived from known plaintext
    # -------------------------------------------------------------------
    phase5_start = attempts
    notes.append("Phase 5: Known-plaintext-derived primers")
    # If we know EAST at position 21, we can try to derive what the key
    # digits would have been at those positions and work backwards
    for clue, start_pos in ANCHORS:
        for alphabet_name, alphabet in alphabets:
            # For each anchor, compute what key digits would be needed
            needed_keys: list[int] = []
            valid = True
            for i, (ct_char, pt_char) in enumerate(zip(ct[start_pos:start_pos + len(clue)], clue)):
                if ct_char not in alphabet or pt_char not in alphabet:
                    valid = False
                    break
                ct_idx = alphabet.index(ct_char)
                pt_idx = alphabet.index(pt_char)
                needed_keys.append((ct_idx - pt_idx) % 26)
            if not valid or not needed_keys:
                continue
            # The needed keys at positions start_pos..start_pos+len(clue)-1
            # must satisfy key[i] = (key[i-1] + key[i-2]) mod 10 for the
            # Gromark recurrence. Check if they do (mod 10).
            needed_mod10 = [k % 10 for k in needed_keys]
            recurrence_ok = True
            for i in range(2, len(needed_mod10)):
                if needed_mod10[i] != (needed_mod10[i - 1] + needed_mod10[i - 2]) % 10:
                    recurrence_ok = False
                    break
            notes.append(
                f"  Anchor {clue}@{start_pos} [{alphabet_name}]: "
                f"needed_keys={needed_mod10[:6]}... recurrence={'OK' if recurrence_ok else 'FAIL'}"
            )
            if recurrence_ok and len(needed_mod10) >= 2:
                # Try to work backwards to find the primer
                # The key at position start_pos was generated from the primer
                # We know key[start_pos] and key[start_pos+1]
                # Work backwards: key[i-2] = (key[i] - key[i-1]) mod 10
                key_backward = list(reversed(needed_mod10[:2]))  # Start from positions start_pos+1, start_pos
                pos = start_pos
                while pos > 0 and len(key_backward) < start_pos + 5:
                    pos -= 1
                    # key[pos] = (key[pos+2] - key[pos+1]) mod 10
                    # But we need to reconstruct... key[pos+2] = (key[pos+1] + key[pos]) mod 10
                    # => key[pos] = (key[pos+2] - key[pos+1]) mod 10
                    next_val = (key_backward[-2] - key_backward[-1]) % 10
                    key_backward.append(next_val)
                full_key = list(reversed(key_backward))
                # The primer is the first 2-5 digits
                for primer_len in range(2, min(6, len(full_key) + 1)):
                    primer_derived = full_key[:primer_len]
                    process_primer(primer_derived, alphabet_name, alphabet)
    notes.append(f"  KP-derived: {attempts - phase5_start} attempts, best_score={best_score}")

    # -------------------------------------------------------------------
    # Collect and rank results
    # -------------------------------------------------------------------
    notes.append(f"Total attempts: {attempts}")
    notes.append(f"Promising results found: {len(best_results)}")

    # Sort all results by score and take top candidates
    best_results.sort(key=lambda x: x[0], reverse=True)

    # Cap at top 50 for candidate generation
    for score, primer, alphabet_name, pt, char_matches, full_matches in best_results[:50]:
        primer_str = "".join(str(d) for d in primer)
        ic = calculate_ioc(pt)
        candidate = build_ranked_candidate(
            pt,
            transform_chain=[f"gromark:{alphabet_name}:primer={primer_str}"],
            key_material={
                "cipher": "gromark",
                "primer": primer_str,
                "primer_digits": primer,
                "alphabet": alphabet_name,
                "anchor_char_matches": char_matches,
                "anchor_full_matches": full_matches,
                "ic": round(ic, 6),
            },
        )
        candidates.append(candidate)

    # Report top 10 in notes
    for i, (score, primer, alphabet_name, pt, char_matches, full_matches) in enumerate(best_results[:10]):
        primer_str = "".join(str(d) for d in primer)
        ic = calculate_ioc(pt)
        notes.append(
            f"  #{i+1}: primer={primer_str} [{alphabet_name}] "
            f"score={score} chars={char_matches} fulls={full_matches} "
            f"IC={ic:.5f} preview={pt[:40]}..."
        )

    # If no candidates survived filtering, generate baseline
    if not candidates:
        notes.append("No Gromark decryption passed anchor threshold; adding baseline.")
        candidate = build_ranked_candidate(
            ct,
            transform_chain=["gromark:no_match"],
            key_material={"cipher": "gromark", "status": "no_match"},
        )
        candidates.append(candidate)

    candidates = dedupe_ranked_candidates(candidates)
    return build_strategy_result(SPEC, candidates, attempts=attempts, notes=notes)
