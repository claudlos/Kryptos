"""Shared crypto helpers, scoring functions, and result formatting."""

from __future__ import annotations

import hashlib
from statistics import mean
from typing import TYPE_CHECKING, Any

from .constants import (
    ANCHOR_COMPONENT_CLUES,
    CONTEXT_CLUES,
    DEFAULT_KEYWORDS,
    DEFAULT_PRIMERS,
    KNOWN_PLAINTEXT_CLUES,
    KRYPTOS_ALPHABET,
    K1_3_WORDS,
    META_CLUES,
    POLYBIUS_ALPHABET,
    STANDARD_ALPHABET,
)
from .models import SearchMetrics, StrategyResult

if TYPE_CHECKING:
    from .corpora import CorpusBundle
    from .runtime import StrategyRuntimeConfig

FRACTIONATION_TARGETS = [
    *KNOWN_PLAINTEXT_CLUES,
    *ANCHOR_COMPONENT_CLUES,
    "BERLIN",
    "CLOCK",
    "LANGLEY",
    "CIA",
    "MESSAGE",
    "WORLD",
    "EGYPT",
]

ENGLISH_SHAPE_TARGETS = ["THE", "ING", "ION", "ENT", "HER", "ERE", "THA", "TIO", "TER", "ATI"]

SCORER_WEIGHTS: dict[str, dict[str, int]] = {
    "anchor-first": {"anchor": 50, "language": 20, "domain": 15, "entity": 10, "structure": 5},
    "running-key": {"anchor": 45, "language": 20, "domain": 10, "entity": 5, "structure": 20},
    "geo-route": {"anchor": 35, "language": 15, "domain": 20, "entity": 20, "structure": 10},
}

BASE_DOMAIN_TERMS = tuple(sorted({keyword for clue in CONTEXT_CLUES + META_CLUES for keyword in clue["keywords"]}))
BASE_ENTITY_TERMS = tuple(sorted({"BERLIN", "CLOCK", "WORLD", "EGYPT", "ALEXANDERPLATZ", "ZEITUHR", "LANGLEY", "CIA"}))
ANCHOR_COMPONENT_POSITIONS = tuple(
    (clue, int(details["start_index"]) - 1)
    for clue, details in ANCHOR_COMPONENT_CLUES.items()
)

def normalize_letters(text: str) -> str:
    return "".join(char for char in text.upper() if char.isalpha())


def calculate_ioc(text: str) -> float:
    normalized = normalize_letters(text)
    n = len(normalized)
    if n <= 1:
        return 0.0
    counts = {char: 0 for char in STANDARD_ALPHABET}
    for char in normalized:
        counts[char] += 1
    return sum(value * (value - 1) for value in counts.values()) / (n * (n - 1))


def chunked_ioc(text: str, width: int = 12) -> float:
    normalized = normalize_letters(text)
    if not normalized:
        return 0.0
    chunks = [normalized[index:index + width] for index in range(0, len(normalized), width)]
    valid_chunks = [chunk for chunk in chunks if len(chunk) > 1]
    if not valid_chunks:
        return calculate_ioc(normalized)
    return mean(calculate_ioc(chunk) for chunk in valid_chunks)


def build_quagmire_tableau() -> list[str]:
    return [KRYPTOS_ALPHABET[index:] + KRYPTOS_ALPHABET[:index] for index in range(26)]


def decrypt_quagmire_char(cipher_char: str, key_char: str, tableau: list[str]) -> str:
    if key_char not in KRYPTOS_ALPHABET or cipher_char not in KRYPTOS_ALPHABET:
        return cipher_char
    row = tableau[KRYPTOS_ALPHABET.index(key_char)]
    return KRYPTOS_ALPHABET[row.index(cipher_char)] if cipher_char in row else cipher_char


def decrypt_quagmire_running(ciphertext: str, key_string: str, tableau: list[str] | None = None) -> str:
    tableau = tableau or build_quagmire_tableau()
    plaintext = []
    for index, cipher_char in enumerate(ciphertext):
        key_char = key_string[index % len(key_string)]
        plaintext.append(decrypt_quagmire_char(cipher_char, key_char, tableau))
    return "".join(plaintext)


def decrypt_quagmire_autokey(
    ciphertext: str,
    primer: str,
    mode: str = "plain",
    tableau: list[str] | None = None,
) -> str:
    tableau = tableau or build_quagmire_tableau()
    plaintext = []
    current_key = list(primer.upper())
    for index, cipher_char in enumerate(ciphertext):
        key_char = current_key[index]
        plain_char = decrypt_quagmire_char(cipher_char, key_char, tableau)
        plaintext.append(plain_char)
        if mode == "plain":
            current_key.append(plain_char)
        elif mode == "cipher":
            current_key.append(cipher_char)
        else:
            raise ValueError(f"Unsupported autokey mode: {mode}")
    return "".join(plaintext)


def encrypt_vigenere_standard(plaintext: str, key_string: str) -> str:
    ciphertext = []
    for index, plain_char in enumerate(plaintext):
        key_char = key_string[index % len(key_string)]
        if key_char not in STANDARD_ALPHABET or plain_char not in STANDARD_ALPHABET:
            ciphertext.append(plain_char)
            continue
        shift = STANDARD_ALPHABET.index(key_char)
        plain_index = STANDARD_ALPHABET.index(plain_char)
        ciphertext.append(STANDARD_ALPHABET[(plain_index + shift) % 26])
    return "".join(ciphertext)


def decrypt_vigenere_standard(ciphertext: str, key_string: str) -> str:
    plaintext = []
    for index, cipher_char in enumerate(ciphertext):
        key_char = key_string[index % len(key_string)]
        if key_char not in STANDARD_ALPHABET or cipher_char not in STANDARD_ALPHABET:
            plaintext.append(cipher_char)
            continue
        shift = STANDARD_ALPHABET.index(key_char)
        cipher_index = STANDARD_ALPHABET.index(cipher_char)
        plaintext.append(STANDARD_ALPHABET[(cipher_index - shift) % 26])
    return "".join(plaintext)


def encrypt_vigenere_autokey(plaintext: str, primer: str, mode: str = "plain") -> str:
    ciphertext = []
    key_stream = list(normalize_letters(primer))
    for index, plain_char in enumerate(plaintext):
        key_char = key_stream[index]
        shift = STANDARD_ALPHABET.index(key_char)
        cipher_char = STANDARD_ALPHABET[(STANDARD_ALPHABET.index(plain_char) + shift) % 26]
        ciphertext.append(cipher_char)
        key_stream.append(plain_char if mode == "plain" else cipher_char)
    return "".join(ciphertext)


def decrypt_vigenere_autokey(ciphertext: str, primer: str, mode: str = "plain") -> str:
    plaintext = []
    key_stream = list(normalize_letters(primer))
    for index, cipher_char in enumerate(ciphertext):
        key_char = key_stream[index]
        shift = STANDARD_ALPHABET.index(key_char)
        plain_char = STANDARD_ALPHABET[(STANDARD_ALPHABET.index(cipher_char) - shift) % 26]
        plaintext.append(plain_char)
        key_stream.append(plain_char if mode == "plain" else cipher_char)
    return "".join(plaintext)


def decrypt_vigenere_window(ciphertext: str, key_string: str) -> str:
    return decrypt_vigenere_standard(ciphertext, key_string)


def generate_polybius_square(keyword: str) -> str:
    square = []
    seen = set()
    for char in normalize_letters(keyword).replace("J", "I"):
        if char not in seen and char in POLYBIUS_ALPHABET:
            seen.add(char)
            square.append(char)
    for char in POLYBIUS_ALPHABET:
        if char not in seen:
            seen.add(char)
            square.append(char)
    return "".join(square)


def mutate_polybius_square(square: str, mutation_id: int, swaps: int = 4) -> str:
    if mutation_id <= 0:
        return square
    chars = list(square)
    seed = mutation_id * 19937 + 123456789
    for _ in range(swaps):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        left = seed % len(chars)
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        right = seed % len(chars)
        chars[left], chars[right] = chars[right], chars[left]
    return "".join(chars)


def get_polybius_coordinates(char: str, square: str) -> tuple[int | None, int | None]:
    normalized = char.upper().replace("J", "I")
    if normalized not in POLYBIUS_ALPHABET:
        return None, None
    index = square.index(normalized)
    return index // 5, index % 5


def bifid_encrypt(period: int, plaintext: str, square: str) -> str:
    ciphertext = []
    for block_start in range(0, len(plaintext), period):
        block = plaintext[block_start:block_start + period]
        rows: list[int] = []
        cols: list[int] = []
        letters: list[str] = []
        for char in block:
            row, col = get_polybius_coordinates(char, square)
            if row is None or col is None:
                continue
            rows.append(row)
            cols.append(col)
            letters.append(char)
        if not letters:
            ciphertext.append(block)
            continue
        stream = rows + cols
        encoded = []
        for index in range(0, len(stream), 2):
            row = stream[index]
            col = stream[index + 1]
            encoded.append(square[row * 5 + col])
        ciphertext.append("".join(encoded))
    return "".join(ciphertext)


def decrypt_bifid(period: int, ciphertext: str, square: str) -> str:
    plaintext = []
    for block_start in range(0, len(ciphertext), period):
        block = ciphertext[block_start:block_start + period]
        coords: list[int] = []
        valid_chars = 0
        for char in block:
            row, col = get_polybius_coordinates(char, square)
            if row is None or col is None:
                continue
            coords.extend([row, col])
            valid_chars += 1
        if not valid_chars:
            plaintext.append(block)
            continue
        rows = coords[:valid_chars]
        cols = coords[valid_chars:]
        decoded = []
        for row, col in zip(rows, cols):
            decoded.append(square[row * 5 + col])
        plaintext.append("".join(decoded))
    return "".join(plaintext)


def get_vigenere_shifts(plaintext: str, ciphertext: str) -> tuple[list[int], str]:
    shifts: list[int] = []
    for plain_char, cipher_char in zip(plaintext, ciphertext):
        plain_value = ord(plain_char) - 65
        cipher_value = ord(cipher_char) - 65
        shifts.append((cipher_value - plain_value) % 26)
    return shifts, "".join(chr(shift + 65) for shift in shifts)


def iter_known_plaintext_segments(text: str) -> list[tuple[str, int, str]]:
    segments = []
    for clue, details in KNOWN_PLAINTEXT_CLUES.items():
        start_index = int(details["start_index"]) - 1
        segment = text[start_index:start_index + len(clue)]
        segments.append((clue, start_index, segment))
    return segments


def iter_anchor_components(text: str) -> list[tuple[str, int, str]]:
    segments = []
    for clue, details in ANCHOR_COMPONENT_CLUES.items():
        start_index = int(details["start_index"]) - 1
        segment = text[start_index:start_index + len(clue)]
        segments.append((clue, start_index, segment))
    return segments


def extract_clue_hits(text: str) -> list[str]:
    return [clue for clue in KNOWN_PLAINTEXT_CLUES if clue in text]


def score_substrings(text: str, targets: list[str], full_match_weight: int = 1000) -> int:
    score = 0
    for target in targets:
        if target in text:
            score += full_match_weight
        for size, weight in ((4, 25), (3, 5), (2, 1)):
            if len(target) < size:
                continue
            for start in range(len(target) - size + 1):
                if target[start:start + size] in text:
                    score += weight
    return score


def clue_overlap_score(text: str) -> int:
    return score_substrings(text, list(KNOWN_PLAINTEXT_CLUES))


def anchor_component_char_matches(text: str) -> int:
    return sum(sum(1 for left, right in zip(segment, clue) if left == right) for clue, _start, segment in iter_anchor_components(text))


def anchor_alignment_score(text: str, per_char_weight: int = 180, full_match_weight: int = 3500) -> int:
    score = 0
    for clue, _start_index, segment in iter_known_plaintext_segments(text):
        score += sum(1 for left, right in zip(segment, clue) if left == right) * per_char_weight
        score += score_substrings(segment, [clue], full_match_weight=full_match_weight)
    for clue, _start_index, segment in iter_anchor_components(text):
        score += sum(1 for left, right in zip(segment, clue) if left == right) * (per_char_weight // 2)
        if segment == clue:
            score += full_match_weight // 2
    return score


def collect_context_terms(corpus_bundle: CorpusBundle | None = None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if corpus_bundle is None:
        return BASE_DOMAIN_TERMS, BASE_ENTITY_TERMS
    domain_terms = tuple(dict.fromkeys([*BASE_DOMAIN_TERMS, *corpus_bundle.domain_terms]))
    entity_terms = tuple(dict.fromkeys([*BASE_ENTITY_TERMS, *corpus_bundle.entity_terms]))
    return domain_terms, entity_terms


def anchor_component_score(text: str) -> int:
    total_chars = sum(len(clue) for clue in ANCHOR_COMPONENT_CLUES)
    char_matches = anchor_component_char_matches(text)
    full_components = sum(1 for clue, _start, segment in iter_anchor_components(text) if segment == clue)
    full_combined = sum(1 for clue, _start, segment in iter_known_plaintext_segments(text) if segment == clue)
    overlap = min(score_substrings(text, list(ANCHOR_COMPONENT_CLUES) + list(KNOWN_PLAINTEXT_CLUES), full_match_weight=150), 300)
    score = (
        (char_matches / total_chars) * 620
        + (full_components / max(len(ANCHOR_COMPONENT_CLUES), 1)) * 230
        + (full_combined / max(len(KNOWN_PLAINTEXT_CLUES), 1)) * 100
        + overlap
    )
    return max(0, min(1000, round(score)))


def language_shape_score(text: str) -> int:
    normalized = normalize_letters(text)
    if not normalized:
        return 0
    shape_hits = min(score_substrings(normalized, ENGLISH_SHAPE_TARGETS, full_match_weight=120), 600)
    route_hits = min(score_substrings(normalized, [word for word in K1_3_WORDS if len(word) >= 4], full_match_weight=80), 500)
    vowel_ratio = sum(1 for char in normalized if char in "AEIOUY") / len(normalized)
    vowel_score = max(0.0, 1.0 - abs(vowel_ratio - 0.38) / 0.30)
    ioc_score = max(0.0, 1.0 - abs(chunked_ioc(normalized) - 0.062) / 0.06)
    return max(0, min(1000, round(shape_hits * 0.6 + route_hits * 0.2 + vowel_score * 120 + ioc_score * 180)))


def domain_term_score(text: str, corpus_bundle: CorpusBundle | None = None) -> int:
    domain_terms, _ = collect_context_terms(corpus_bundle)
    hits = sum(1 for term in domain_terms if len(term) >= 4 and term in text)
    phrase_bonus = min(score_substrings(text, domain_terms[:80], full_match_weight=90), 650)
    return max(0, min(1000, hits * 35 + phrase_bonus // 2))


def entity_term_score(text: str, corpus_bundle: CorpusBundle | None = None) -> int:
    _, entity_terms = collect_context_terms(corpus_bundle)
    hits = sum(1 for term in entity_terms if term in text)
    clustered = sum(1 for term in entity_terms if len(term) >= 5 and term in text and text.count(term) > 1)
    return max(0, min(1000, hits * 90 + clustered * 60))


def periodic_redundancy_score(text: str) -> int:
    normalized = normalize_letters(text)
    if len(normalized) < 8:
        return 0
    score = 0
    for width in range(2, 9):
        chunks = [normalized[index:index + width] for index in range(0, len(normalized), width)]
        repeated = len(chunks) - len(set(chunks))
        if repeated > 0:
            score += repeated * 35
    inferred = sum(1 for key_length in range(1, 13) if infer_repeating_vigenere_key(normalized, key_length) is not None)
    return max(0, min(1000, score + inferred * 140))


def penalty_score(text: str) -> int:
    normalized = normalize_letters(text)
    if not normalized:
        return 1000
    vowel_ratio = sum(1 for char in normalized if char in "AEIOUY") / len(normalized)
    harsh_ratio = sum(1 for char in normalized if char in "QZXJ") / len(normalized)
    penalty = 0
    if vowel_ratio < 0.18 or vowel_ratio > 0.55:
        penalty += 180
    if harsh_ratio > 0.18:
        penalty += round((harsh_ratio - 0.18) * 1200)
    return max(0, min(1000, penalty))


def build_score_breakdown(
    text: str,
    *,
    corpus_bundle: CorpusBundle | None = None,
    scorer_profile: str = "anchor-first",
    structure_hint: int = 0,
) -> dict[str, int]:
    if scorer_profile not in SCORER_WEIGHTS:
        raise ValueError(f"Unsupported scorer profile: {scorer_profile}")
    anchor = anchor_component_score(text)
    language = language_shape_score(text)
    domain = domain_term_score(text, corpus_bundle)
    entity = entity_term_score(text, corpus_bundle)
    structure = max(0, min(1000, periodic_redundancy_score(text) + structure_hint))
    penalty = penalty_score(text)
    weights = SCORER_WEIGHTS[scorer_profile]
    weighted = (
        anchor * weights["anchor"]
        + language * weights["language"]
        + domain * weights["domain"]
        + entity * weights["entity"]
        + structure * weights["structure"]
    ) / 100
    total = max(0, min(1000, round(weighted - (penalty * 0.35))))
    return {
        "anchor": anchor,
        "language": language,
        "domain": domain,
        "entity": entity,
        "structure": structure,
        "penalty": penalty,
        "total": total,
    }


def fractionation_candidate_score(text: str) -> int:
    return build_score_breakdown(text)["total"]


def infer_repeating_vigenere_key(ciphertext: str, key_length: int) -> str | None:
    if key_length <= 0:
        raise ValueError("key_length must be positive")

    resolved_slots: dict[int, int] = {}
    for clue, start_index, segment in iter_known_plaintext_segments(ciphertext):
        if len(segment) != len(clue):
            return None
        for offset, (cipher_char, plain_char) in enumerate(zip(segment, clue)):
            if cipher_char not in STANDARD_ALPHABET or plain_char not in STANDARD_ALPHABET:
                return None
            shift = (STANDARD_ALPHABET.index(cipher_char) - STANDARD_ALPHABET.index(plain_char)) % 26
            slot = (start_index + offset) % key_length
            if slot in resolved_slots and resolved_slots[slot] != shift:
                return None
            resolved_slots[slot] = shift

    if len(resolved_slots) != key_length:
        return None

    return "".join(chr(resolved_slots[index] + 65) for index in range(key_length))


def preview_text(text: str, limit: int = 72) -> str:
    stripped = text.strip()
    if len(stripped) <= limit:
        return stripped
    return f"{stripped[:limit]}..."


def preview_hash(text: str) -> str:
    return hashlib.sha1(preview_text(text, limit=96).encode("utf-8")).hexdigest()[:16]


def transform_family(transform_chain: list[str]) -> tuple[str, ...]:
    return tuple(step.split(":", 1)[0] for step in transform_chain)


def candidate_secondary_total(candidate: dict[str, object]) -> int:
    totals = []
    if "anchor_first_total" in candidate:
        totals.append(int(candidate["anchor_first_total"]))
    if "geo_route_total" in candidate:
        totals.append(int(candidate["geo_route_total"]))
    secondary_scores = candidate.get("secondary_scores")
    if isinstance(secondary_scores, dict):
        for breakdown in secondary_scores.values():
            if isinstance(breakdown, dict) and "total" in breakdown:
                totals.append(int(breakdown["total"]))
    return max(totals, default=0)


def build_ranked_candidate(
    text: str,
    *,
    transform_chain: list[str],
    corpus_bundle: CorpusBundle | None = None,
    scorer_profile: str = "anchor-first",
    key_material: dict[str, Any] | None = None,
    corpus_id: str | None = None,
    structure_hint: int = 0,
) -> dict[str, object]:
    breakdown = build_score_breakdown(
        text,
        corpus_bundle=corpus_bundle,
        scorer_profile=scorer_profile,
        structure_hint=structure_hint,
    )
    return {
        "rank": 0,
        "total_score": breakdown["total"],
        "breakdown": breakdown,
        "transform_chain": transform_chain,
        "key_material": key_material or {},
        "corpus_id": corpus_id,
        "preview": preview_text(text),
        "matched_clues": extract_clue_hits(text),
        "plaintext": text,
    }


def dedupe_ranked_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: list[dict[str, object]] = []
    seen_signatures: set[tuple[tuple[str, ...], str]] = set()
    for candidate in sort_ranked_candidates(candidates):
        signature = (
            transform_family(list(candidate["transform_chain"])),
            preview_hash(str(candidate["preview"])),
        )
        if signature in seen_signatures:
            continue
        deduped.append(candidate)
        seen_signatures.add(signature)
    return sort_ranked_candidates(deduped)


def rotate_text(text: str, delta: int) -> str:
    if not text:
        return text
    shift = delta % len(text)
    if shift == 0:
        return text
    return text[shift:] + text[:shift]


def score_displacement_alignment(text: str, delta: int) -> dict[str, int]:
    displacement_matches = 0
    exact_components = 0
    for clue, start_index in ANCHOR_COMPONENT_POSITIONS:
        displaced_start = start_index + delta
        displaced_end = displaced_start + len(clue)
        if displaced_start < 0 or displaced_end > len(text):
            continue
        component_matches = sum(
            1
            for left, right in zip(text[displaced_start:displaced_end], clue)
            if left == right
        )
        displacement_matches += component_matches
        if component_matches == len(clue):
            exact_components += 1
    proximity_bonus = 45 if -6 <= delta <= 6 else 25 if -12 <= delta <= 12 else 10
    return {
        "delta": delta,
        "match_count": displacement_matches,
        "exact_components": exact_components,
        "score": displacement_matches * 26 + exact_components * 150 + proximity_bonus,
    }


def select_displacement_offsets(
    text: str,
    *,
    displacement_window: int,
    limit: int,
    preferred_deltas: tuple[int, ...] = (),
) -> list[dict[str, int]]:
    scored_offsets = {
        delta: score_displacement_alignment(text, delta)
        for delta in range(-displacement_window, displacement_window + 1)
        if delta != 0
    }
    selected: list[dict[str, int]] = []
    seen_deltas: set[int] = set()
    for delta in preferred_deltas:
        if delta == 0 or abs(delta) > displacement_window or delta in seen_deltas:
            continue
        selected.append(scored_offsets.get(delta, score_displacement_alignment(text, delta)))
        seen_deltas.add(delta)
        if len(selected) >= limit:
            return selected

    ranked_offsets = sorted(
        scored_offsets.values(),
        key=lambda details: (
            details["score"],
            details["exact_components"],
            details["match_count"],
            -abs(details["delta"]),
        ),
        reverse=True,
    )
    for details in ranked_offsets:
        delta = int(details["delta"])
        if delta in seen_deltas or details["match_count"] <= 0:
            continue
        selected.append(details)
        seen_deltas.add(delta)
        if len(selected) >= limit:
            break

    if selected:
        return selected
    return ranked_offsets[:1]


def build_displacement_route_candidates(
    text: str,
    *,
    transform_chain: list[str],
    corpus_bundle: CorpusBundle | None = None,
    scorer_profile: str = "anchor-first",
    key_material: dict[str, Any] | None = None,
    corpus_id: str | None = None,
    displacement_window: int = 24,
    route_followup_limit: int = 3,
    preferred_deltas: tuple[int, ...] = (),
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for alignment in select_displacement_offsets(
        text,
        displacement_window=displacement_window,
        limit=max(route_followup_limit, 1),
        preferred_deltas=preferred_deltas,
    ):
        delta = int(alignment["delta"])
        rotated = rotate_text(text, delta)
        structure_hint = min(320, 160 + int(alignment["score"]) // 2)
        anchor_breakdown = build_score_breakdown(
            rotated,
            corpus_bundle=corpus_bundle,
            scorer_profile="anchor-first",
            structure_hint=structure_hint,
        )
        geo_breakdown = build_score_breakdown(
            rotated,
            corpus_bundle=corpus_bundle,
            scorer_profile="geo-route",
            structure_hint=structure_hint,
        )
        if scorer_profile == "geo-route":
            primary_breakdown = geo_breakdown
        elif scorer_profile == "anchor-first":
            primary_breakdown = anchor_breakdown
        else:
            primary_breakdown = build_score_breakdown(
                rotated,
                corpus_bundle=corpus_bundle,
                scorer_profile=scorer_profile,
                structure_hint=structure_hint,
            )
        candidate = {
            "rank": 0,
            "total_score": primary_breakdown["total"],
            "breakdown": primary_breakdown,
            "anchor_first_total": anchor_breakdown["total"],
            "geo_route_total": geo_breakdown["total"],
            "secondary_scores": {
                "anchor-first": anchor_breakdown,
                "geo-route": geo_breakdown,
            },
            "transform_chain": [*transform_chain, f"displacement:delta={delta}"],
            "key_material": {
                **(key_material or {}),
                "displacement_delta": delta,
                "alignment_score": int(alignment["score"]),
                "alignment_matches": int(alignment["match_count"]),
                "alignment_exact_components": int(alignment["exact_components"]),
            },
            "corpus_id": corpus_id,
            "preview": preview_text(rotated),
            "matched_clues": extract_clue_hits(rotated),
            "plaintext": rotated,
        }
        candidates.append(candidate)
    return dedupe_ranked_candidates(candidates)


def sort_ranked_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    ranked = sorted(
        candidates,
        key=lambda candidate: (
            int(candidate["total_score"]),
            candidate_secondary_total(candidate),
            int(candidate["breakdown"]["anchor"]),
            len(candidate["matched_clues"]),
            int(candidate["breakdown"]["language"]),
        ),
        reverse=True,
    )
    for rank, candidate in enumerate(ranked, start=1):
        candidate["rank"] = rank
    return ranked


def ensure_top_candidates(result: StrategyResult, *, scorer_profile: str = "anchor-first") -> StrategyResult:
    if result.artifacts.get("top_candidates"):
        return result
    fallback_text = str(result.artifacts.get("best_text") or result.best_preview)
    if not fallback_text:
        return result
    candidate = build_ranked_candidate(fallback_text, transform_chain=[result.name], scorer_profile=scorer_profile)
    result.artifacts["top_candidates"] = [candidate]
    return result


def build_strategy_result(
    spec: dict[str, str],
    candidates: list[dict[str, object]],
    *,
    attempts: int,
    notes: list[str] | None = None,
) -> StrategyResult:
    ranked = sort_ranked_candidates(candidates)
    best = ranked[0]
    summary = (
        f"Top candidate scored {best['total_score']}/1000 via {' -> '.join(best['transform_chain'])}."
        if best["total_score"]
        else "No retained candidate exceeded the current scoring floor."
    )
    status = "candidate" if int(best["total_score"]) >= 300 else "no_match"
    return StrategyResult(
        strategy_id=spec["id"],
        name=spec["name"],
        objective=spec["objective"],
        hypothesis=spec["hypothesis"],
        status=status,
        summary=summary,
        best_preview=str(best["preview"]),
        matched_clues=list(best["matched_clues"]),
        metrics=SearchMetrics(attempts=attempts, unique_attempts=attempts),
        notes=notes or [],
        artifacts={
            "top_candidates": ranked,
            "best_text": best["plaintext"],
        },
    )


def analyze_layered_candidate(
    text: str,
    max_key_length: int = 12,
    *,
    config: StrategyRuntimeConfig | None = None,
    corpus_bundle: CorpusBundle | None = None,
    scorer_profile: str = "anchor-first",
) -> dict[str, object]:
    if config is not None:
        max_key_length = config.max_post_key_length
        corpus_bundle = config.corpora
        scorer_profile = config.scorer_profile
    candidates = [
        {
            "mode": "direct",
            **build_ranked_candidate(text, transform_chain=["direct"], corpus_bundle=corpus_bundle, scorer_profile=scorer_profile),
            "derived_key": None,
            "key_length": None,
        }
    ]

    for key_length in range(1, max_key_length + 1):
        key = infer_repeating_vigenere_key(text, key_length)
        if key is None:
            continue
        candidate_text = decrypt_vigenere_standard(text, key)
        ranked = build_ranked_candidate(
            candidate_text,
            transform_chain=["direct", f"post_vigenere:{key}"],
            corpus_bundle=corpus_bundle,
            scorer_profile=scorer_profile,
            key_material={"mode": "repeating", "key": key, "key_length": key_length},
            structure_hint=max(0, 240 - key_length * 12),
        )
        candidates.append({
            "mode": "post_vigenere",
            **ranked,
            "derived_key": key,
            "key_length": key_length,
        })

    primers = DEFAULT_PRIMERS[:8]
    if config is not None:
        primers = config.ordered_primers(list(primers))
    for primer in primers:
        for mode in ("plain", "cipher"):
            candidate_text = decrypt_vigenere_autokey(text, primer, mode=mode)
            ranked = build_ranked_candidate(
                candidate_text,
                transform_chain=["direct", f"post_autokey:{mode}:{primer}"],
                corpus_bundle=corpus_bundle,
                scorer_profile=scorer_profile,
                key_material={"mode": f"autokey-{mode}", "primer": primer},
                structure_hint=120,
            )
            candidates.append({
                "mode": "post_autokey",
                **ranked,
                "derived_key": primer,
                "key_length": len(primer),
            })

    from .transposition import hillclimb_permutation, identity_permutation, keyword_permutation

    widths = [width for width in (5, 7, 9, 12) if width <= len(text) - 1]
    if config is not None:
        preferred_widths = [
            int(width)
            for width in config.adaptive_guidance.get("preferred_widths") or []
            if isinstance(width, int) and width <= len(text) - 1
        ]
        width_pool = list(dict.fromkeys([*widths, *preferred_widths]))
        periodic_width_budget = config.budgeted_limit(4, family="periodic_transposition", max_extra=2, ceiling=len(width_pool))
        widths = list(config.ordered_widths(width_pool))[:periodic_width_budget]
        periodic_keyword_budget = config.budgeted_limit(2, family="periodic_transposition", max_extra=2, ceiling=len(DEFAULT_KEYWORDS))
        keyword_seeds = list(config.ordered_keywords(list(DEFAULT_KEYWORDS)))[:periodic_keyword_budget]
    else:
        keyword_seeds = list(DEFAULT_KEYWORDS[:2])
    for width in widths:
        for seed_keyword in keyword_seeds:
            for permutation in (identity_permutation(width), keyword_permutation(seed_keyword, width)):
                for fill_mode, read_mode in (("row", "column"), ("column", "row")):
                    def _score(candidate_text: str) -> tuple[int, dict[str, int]]:
                        breakdown = build_score_breakdown(
                            candidate_text,
                            corpus_bundle=corpus_bundle,
                            scorer_profile=scorer_profile,
                            structure_hint=180,
                        )
                        return breakdown["total"], breakdown
                    result = hillclimb_permutation(
                        text,
                        width,
                        permutation,
                        _score,
                        fill_mode=fill_mode,
                        read_mode=read_mode,
                        reverse_rows=False,
                        reverse_columns=False,
                    )
                    ranked = build_ranked_candidate(
                        str(result["plaintext"]),
                        transform_chain=["direct", f"post_periodic_transposition:w{width}:{fill_mode}->{read_mode}"],
                        corpus_bundle=corpus_bundle,
                        scorer_profile=scorer_profile,
                        key_material={
                            "keyword": seed_keyword,
                            "width": width,
                            "permutation": list(result["permutation"]),
                            "fill_mode": fill_mode,
                            "read_mode": read_mode,
                        },
                        structure_hint=180,
                    )
                    candidates.append({
                        "mode": "post_periodic_transposition",
                        **ranked,
                        "derived_key": seed_keyword,
                        "key_length": width,
                    })

    best = sort_ranked_candidates(candidates)[0]
    return {
        "mode": best["mode"],
        "score": best["total_score"],
        "derived_key": best.get("derived_key"),
        "key_length": best.get("key_length"),
        "plaintext": best["plaintext"],
        "matched_clues": best["matched_clues"],
        "preview": best["preview"],
        "breakdown": best["breakdown"],
        "transform_chain": best["transform_chain"],
        "key_material": best["key_material"],
    }


def format_result(result: StrategyResult) -> str:
    ensure_top_candidates(result)
    lines = [
        f"[{result.strategy_id}] {result.name}",
        f"Status: {result.status}",
        result.summary,
    ]
    if result.matched_clues:
        lines.append(f"Matched clues: {', '.join(result.matched_clues)}")
    if result.best_preview:
        lines.append(f"Preview: {result.best_preview}")
    top_candidates = result.artifacts.get("top_candidates") or []
    if top_candidates:
        lines.append(f"Best score: {top_candidates[0]['total_score']}/1000")
    if result.metrics.attempts:
        metrics = [f"attempts={result.metrics.attempts}"]
        if result.metrics.unique_attempts is not None:
            metrics.append(f"unique={result.metrics.unique_attempts}")
        if result.metrics.repeated_attempts is not None:
            metrics.append(f"repeated={result.metrics.repeated_attempts}")
        if result.metrics.elapsed_seconds is not None:
            metrics.append(f"elapsed={result.metrics.elapsed_seconds:.4f}s")
        lines.append("Metrics: " + ", ".join(metrics))
    for note in result.notes:
        lines.append(f"- {note}")
    return "\n".join(lines)
