"""Source-of-truth metadata for strategy catalog and dashboard content."""

from __future__ import annotations

from copy import deepcopy

from .common import get_vigenere_shifts
from .constants import (
    ANCHOR_COMBINED_CLUES,
    ANCHOR_COMPONENT_CLUES,
    CONTEXT_CLUES,
    K4,
    META_CLUES,
)

PROJECT_METADATA = {
    "title": "Kryptos K4 Research Dashboard",
    "tagline": "A grounded view of the repository's hypotheses, benchmarks, and latest structured runs.",
    "repo_url": "https://github.com/claudlos/Kryptos",
    "website_url": "https://claudlos.github.io/Kryptos/",
}

BENCHMARKS = [
    {
        "label": "Python CPU sweep",
        "speed_per_second": 18133,
        "display_speed": "18,133/sec",
        "kind": "historical",
        "notes": "Repository baseline for the pre-compiled Python heuristics.",
    },
    {
        "label": "CPU strategy runner",
        "speed_per_second": 9620,
        "display_speed": "9,620/sec",
        "kind": "historical",
        "notes": "Comparable fixture-first runner for the new corpus-backed K4 methods.",
    },
    {
        "label": "OpenCL GPU sweep",
        "speed_per_second": 7777777,
        "display_speed": "7,777,777/sec",
        "kind": "historical",
        "notes": "Native OpenCL pass targeting an AMD Radeon 680M.",
    },
]

STRATEGY_SPECS = {
    "1": {
        "id": "1",
        "module": "strategy1_quagmire",
        "slug": "quagmire-running-keys",
        "name": "Quagmire III Running Keys",
        "objective": "Test whether the solved K1-K3 plaintexts can act as direct running keys for K4.",
        "hypothesis": "K4 reuses the Kryptos mixed alphabet and one of the earlier panel plaintexts as its key material.",
        "category": "classical",
    },
    "2": {
        "id": "2",
        "module": "strategy2_matrix",
        "slug": "matrix-mask-reassembly",
        "name": "Spatial Matrix Reassembly",
        "objective": "Read padded 7x14 and 14x7 layouts in alternate orders to search for clue-bearing ciphertext runs.",
        "hypothesis": "K4 may hide anchor substrings through simple geometric rearrangement before substitution.",
        "category": "transposition",
    },
    "3": {
        "id": "3",
        "module": "strategy3_ioc_hillclimb",
        "slug": "hybrid-transposition-search",
        "name": "Hybrid Transposition Search",
        "objective": "Use hill climbing with clue overlap and local IoC heuristics to rank candidate column orders.",
        "hypothesis": "A clue-bearing transposition may surface when column order improves both anchor overlap and local English-like structure.",
        "category": "transposition",
    },
    "4": {
        "id": "4",
        "module": "strategy4_autokey",
        "slug": "quagmire-autokey",
        "name": "Quagmire III Autokey",
        "objective": "Test theme-relevant primers under plain-autokey and cipher-autokey Quagmire variants.",
        "hypothesis": "K4 may bootstrap its own key stream from a short thematic primer.",
        "category": "classical",
    },
    "5": {
        "id": "5",
        "module": "strategy5_grilles",
        "slug": "geometric-grilles",
        "name": "Geometric Grilles",
        "objective": "Apply logical masks across a padded 7x14 grid to test simple grille-style extractions.",
        "hypothesis": "A repeated mask pattern might expose the clue ciphertext as a contiguous extraction.",
        "category": "masking",
    },
    "6": {
        "id": "6",
        "module": "strategy6_chained_autokey",
        "slug": "chained-autokey",
        "name": "Chained Autokey",
        "objective": "Test double-layer Quagmire autokey combinations across theme-relevant primer pairs.",
        "hypothesis": "K4 could be a nested autokey construction requiring two sequential decryptions.",
        "category": "classical",
    },
    "7": {
        "id": "7",
        "module": "strategy7_segmented",
        "slug": "segmented-resets",
        "name": "Segmented Resets",
        "objective": "Split K4 on 'W' and retry running-key and autokey decryption with per-segment resets.",
        "hypothesis": "The repeated 'W' characters may mark segment boundaries or key resets.",
        "category": "segmentation",
    },
    "8": {
        "id": "8",
        "module": "strategy8_shifted_running_key",
        "slug": "shifted-running-keys",
        "name": "Shifted Running Keys",
        "objective": "Exhaustively test all offsets of K1-K3 plaintexts and the KRYPTOS primer as running key material.",
        "hypothesis": "The right offset into prior Kryptos text may align K4 with a standard running-key construction.",
        "category": "classical",
    },
    "9": {
        "id": "9",
        "module": "strategy9_external_keyer",
        "slug": "external-running-key",
        "name": "External Text Running Key",
        "objective": "Slide a historical text window across Howard Carter diary excerpts as candidate running keys.",
        "hypothesis": "An external text tied to the K3 clue may supply the real running key stream for K4.",
        "category": "historical",
    },
    "10": {
        "id": "10",
        "module": "strategy10_fractionation",
        "slug": "fractionation-pipeline",
        "name": "Fractionation Pipeline",
        "objective": "Expand Bifid-style candidates through repeating-key, autokey, and periodic-transposition post layers.",
        "hypothesis": "K4 may require fractionation plus at least one additional keyed layer before the anchor clues emerge.",
        "category": "fractionation",
    },
    "11": {
        "id": "11",
        "module": "strategy11_corpus_running_key",
        "slug": "corpus-running-key",
        "name": "Corpus Running Key",
        "objective": "Slide public corpus windows across K4 and rerank the strongest clue-aligned running-key decryptions.",
        "hypothesis": "Public Howard Carter and official clue corpora contain usable key-stream fragments for a method-reconstruction track.",
        "category": "historical",
    },
    "12": {
        "id": "12",
        "module": "strategy12_periodic_transposition_hillclimb",
        "slug": "periodic-transposition-hillclimb",
        "name": "Periodic Transposition Hillclimb",
        "objective": "Search ragged periodic transposition families with keyword seeds and local permutation hillclimbs.",
        "hypothesis": "K4 may be hiding its anchors inside a periodic transposition that needs stronger ranking than raw brute force.",
        "category": "transposition",
    },
    "13": {
        "id": "13",
        "module": "strategy13_hybrid_pipeline_search",
        "slug": "hybrid-pipeline-search",
        "name": "Hybrid Pipeline Search",
        "objective": "Compose exactly two stages from fractionation, running-key, key-layer, and periodic-transposition families.",
        "hypothesis": "Sanborn's nested hints point to a short pipeline of interacting transforms rather than a single classical cipher.",
        "category": "hybrid",
    },
}


def get_strategy_spec(strategy_id: str) -> dict[str, str]:
    return deepcopy(STRATEGY_SPECS[strategy_id])


def list_strategy_specs() -> list[dict[str, str]]:
    return [deepcopy(spec) for _, spec in sorted(STRATEGY_SPECS.items(), key=lambda item: int(item[0]))]


def anchor_catalog() -> list[dict[str, str | int]]:
    catalog = []
    merged = {**ANCHOR_COMPONENT_CLUES, **ANCHOR_COMBINED_CLUES}
    for clue, details in merged.items():
        start_index = int(details["start_index"]) - 1
        ciphertext = K4[start_index:start_index + len(clue)]
        _, shift_letters = get_vigenere_shifts(clue, ciphertext)
        catalog.append({"plaintext": clue, **details, "shift_letters": shift_letters})
    return catalog


def clue_catalog() -> list[dict[str, object]]:
    catalog: list[dict[str, object]] = [*anchor_catalog()]
    catalog.extend({**entry} for entry in CONTEXT_CLUES)
    catalog.extend({**entry} for entry in META_CLUES)
    return catalog
