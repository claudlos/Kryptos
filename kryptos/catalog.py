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
    "repo_url": "https://github.com/Carlos/Kryptos",
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
    "14": {
        "id": "14",
        "module": "strategy14_displacement_route_search",
        "slug": "displacement-route-search",
        "name": "Displacement Route Search",
        "objective": "Realign top fractionation and transposition candidates with bounded clue-position displacements, then rerank them with route-aware scoring.",
        "hypothesis": "Promising K4 plaintext fragments may already exist in the current search families but be shifted away from the official clue coordinates.",
        "category": "hybrid",
    },
    "15": {
        "id": "15",
        "module": "strategy15_transposition_enumeration",
        "slug": "transposition-enumeration",
        "name": "Z340-Style Transposition Enumeration",
        "objective": "Systematically enumerate all plausible transposition patterns (columnar, route cipher, rail fence, Myszkowski, double columnar) and score each inverse with anchor/language analysis.",
        "hypothesis": "Like the Z340 solution, K4 may conceal its plaintext behind a transposition layer that can be found by exhaustive enumeration of pattern families filtered by known-plaintext anchors.",
        "category": "transposition",
    },
    "16": {
        "id": "16",
        "module": "strategy16_sat_elimination",
        "slug": "sat-constraint-elimination",
        "name": "SAT/SMT Constraint Elimination",
        "objective": "Encode cipher-family hypotheses as Z3 constraint systems and prove satisfiability or impossibility against the known K4 plaintext anchors.",
        "hypothesis": "Formal constraint solving can definitively rule out entire cipher families and parameter ranges, narrowing the search space for K4.",
        "category": "elimination",
    },
    "17": {
        "id": "17",
        "module": "strategy17_method_elimination",
        "slug": "known-plaintext-method-elimination",
        "name": "Known-Plaintext Exhaustive Method Elimination",
        "objective": "Systematically test cipher families against known plaintext positions using pure key-consistency checks to build an elimination matrix.",
        "hypothesis": "Internal key contradictions at known-plaintext positions can eliminate most classical cipher families without needing full decryption.",
        "category": "elimination",
    },
    "18": {
        "id": "18",
        "module": "strategy18_alternating_optimization",
        "slug": "alternating-optimization",
        "name": "Alternating Optimization",
        "objective": "Jointly optimize substitution and transposition layers via Lasry-style alternating optimization with random restarts.",
        "hypothesis": "K4 may be a compound cipher whose substitution and transposition components can be separated and individually hill-climbed in alternating rounds.",
        "category": "hybrid",
    },
    "19": {
        "id": "19",
        "module": "strategy19_mcmc_search",
        "slug": "mcmc-key-search",
        "name": "MCMC Key Search",
        "objective": "Recover Vigenere and transposition keys via Metropolis-Hastings MCMC with n-gram scoring and anchor constraints.",
        "hypothesis": "A stochastic MCMC search can explore the key space more effectively than deterministic hill climbing by accepting occasional score-decreasing moves.",
        "category": "hybrid",
    },
    "20": {
        "id": "20",
        "module": "strategy20_generalized_ic",
        "slug": "generalized-ic-fingerprinting",
        "name": "Generalized IC Fingerprinting",
        "objective": "Compute extended statistical fingerprints (IC, n-gram IC, periodic IC, kappa, chi-squared, entropy) and compare against known cipher family profiles to identify K4's most likely cipher type.",
        "hypothesis": "K4's statistical fingerprint—including IC at various periods, mutual IC with solved panels, and IC after transposition inversion—can narrow the cipher family and reveal whether a transposition layer is present.",
        "category": "analysis",
    },
    "21": {
        "id": "21",
        "module": "strategy21_gromark",
        "slug": "gromark-cipher",
        "name": "Gromark Cipher",
        "objective": "Exhaustively search Gromark cipher primers (Fibonacci-like running key) across 2-5 digit seeds with standard and KRYPTOS-keyed alphabets.",
        "hypothesis": "K4 may use a Gromark cipher—documented in Friedman's Military Cryptanalysis texts cited by Ed Scheidt—where a short numeric primer generates a running key via modular Fibonacci recurrence.",
        "category": "classical",
    },
    "22": {
        "id": "22",
        "module": "strategy22_ml_cipher_classification",
        "slug": "ml-cipher-classification",
        "name": "ML Cipher Type Classification",
        "objective": "Extract statistical features from K4 ciphertext and classify it into probability estimates for each major cipher family using a rule-based decision-tree classifier, then attempt basic decryption for each likely family.",
        "hypothesis": "A systematic multi-feature classifier based on published cipher type profiles (IC, chi-squared, entropy, autocorrelation, bigram analysis) can narrow K4's cipher family and guide targeted decryption attempts.",
        "category": "analysis",
    },
    "23": {
        "id": "23",
        "module": "strategy23_bayesian_analysis",
        "slug": "bayesian-cipher-analysis",
        "name": "Bayesian Cipher Analysis",
        "objective": "Use Gibbs sampling to compute Bayesian posterior distributions over Vigenere and substitution cipher keys, identifying well-constrained key dimensions via posterior concentration analysis.",
        "hypothesis": "Bayesian posterior inference with English bigram log-probabilities and known-plaintext hard constraints can identify key positions that are strongly determined by the data, revealing the most likely cipher period and key.",
        "category": "analysis",
    },
    "24": {
        "id": "24",
        "module": "strategy24_neural_scoring",
        "slug": "neural-language-scoring",
        "name": "Neural Language Model Scoring",
        "objective": "Re-score K4 candidates from diverse transformation families using a comprehensive character-level n-gram language model to identify near-English plaintext.",
        "hypothesis": "A smooth n-gram log-probability score provides a finer gradient toward English than sparse anchor matching, allowing detection of candidates that are 'almost English' but missed by simpler heuristics.",
        "category": "scoring",
    },
    "25": {
        "id": "25",
        "module": "strategy25_alt_substitution_sweep",
        "slug": "alt-substitution-sweep",
        "name": "Beaufort/Quagmire Constraint-First Sweep",
        "objective": "Test Beaufort, Quagmire III (KRYPTOS alphabet), and Autokey Vigenere in the constraint-first framework instead of standard Vigenere.",
        "hypothesis": "The constraint-first approach found 24,966 consistent (transposition, Vigenere) pairs but non-English plaintext outside anchors, suggesting the substitution model itself may be wrong even though transposition is correct.",
        "category": "hybrid",
    },
    "26": {
        "id": "26",
        "module": "strategy26_latitude_investigation",
        "slug": "latitude-investigation",
        "name": "LATITUDE Deep Investigation",
        "objective": "Deeply investigate the LATITUDE transposition keyword finding by testing all cipher models, all periods, geographic keywords, reverse cipher order, and keyword-derived Vigenere keys.",
        "hypothesis": "The LATITUDE keyword producing the highest K4 score is either a genuine signal (connecting to K2's coordinates) or a statistical artifact. Systematic investigation across cipher models and orderings will distinguish signal from noise.",
        "category": "hybrid",
    },
    "27": {
        "id": "27",
        "module": "strategy27_key_derivation",
        "slug": "key-derivation-analysis",
        "name": "Key Derivation Analysis",
        "objective": "Determine whether the 24 constrained Vigenere key characters derive from a systematic process: autokey, running key, rotor mechanism, mathematical recurrence, or known-text substring.",
        "hypothesis": "If K4 uses a principled key generation method, the constrained key characters will exhibit patterns detectable through running-key search, autokey propagation, or mathematical analysis.",
        "category": "analysis",
    },
    "28": {
        "id": "28",
        "module": "strategy28_digraphic_sweep",
        "slug": "digraphic-cipher-sweep",
        "name": "Digraphic Cipher Sweep",
        "objective": "Test digraphic ciphers (Playfair, Four-square, Two-square, Bifid) which process letter pairs, producing near-random IC matching K4's observed IC of 0.036.",
        "hypothesis": "K4's near-random IC is more consistent with a digraphic cipher than a polyalphabetic one. Playfair or Four-square with a Kryptos-relevant keyword square may produce recognizable plaintext.",
        "category": "classical",
    },
    "29": {
        "id": "29",
        "module": "strategy29_dictionary_scoring",
        "slug": "dictionary-full-text-scoring",
        "name": "Dictionary Full-Text Scoring",
        "objective": "Replace bigram MCMC (which overfits noise) with a dictionary-based scorer that demands actual English words, rescoring all existing candidates and running fresh sweeps optimized for word coverage.",
        "hypothesis": "Bigram scoring produces false positives by rewarding common letter pairs in otherwise random text. A dictionary scorer will separate genuine English plaintext from MCMC-fitted noise.",
        "category": "scoring",
    },
    "30": {
        "id": "30",
        "module": "strategy30_monoalphabetic_transposition",
        "slug": "monoalphabetic-transposition",
        "name": "Monoalphabetic + Transposition",
        "objective": "Test simple (monoalphabetic) substitution combined with columnar transposition. With 24 known plaintext chars, a monoalphabetic sub has only 0-2 unknown mappings, making exhaustive search trivial.",
        "hypothesis": "K4 might use a simpler substitution cipher than Vigenere. 24 known characters would almost fully determine a 26-letter substitution alphabet.",
        "category": "elimination",
    },
    "31": {
        "id": "31",
        "module": "strategy31_hill_cipher",
        "slug": "hill-cipher",
        "name": "Hill Cipher + Transposition",
        "objective": "Test 2x2 Hill cipher (matrix multiplication mod 26) on K4, both directly and after transposition. Brute-force all 157,248 invertible 2x2 matrices.",
        "hypothesis": "A Hill cipher produces near-random IC matching K4's 0.036, and 24 known plaintext chars provide enough equations to solve for or verify the key matrix.",
        "category": "elimination",
    },
    "32": {
        "id": "32",
        "module": "strategy32_unknown_source_running_key",
        "slug": "unknown-source-running-key",
        "name": "Unknown-Source Running Key Sweep",
        "objective": "Scan 97-character windows from repository-local text, packaged corpus documents, and solved-panel references as candidate running keys for K4.",
        "hypothesis": "If K4 uses a running key derived from adjacent Kryptos material rather than only the already-tested public documents, a broader mixed source pool may surface stronger anchor-consistent decryptions.",
        "category": "historical",
    },
    "33": {
        "id": "33",
        "module": "strategy33_hill3x3_toolkit",
        "slug": "hill3x3-transposition",
        "name": "Hill 3×3 + Transposition",
        "objective": "Wrap the standalone Hill 3×3 known-plaintext solver and expose its results through the structured toolkit.",
        "hypothesis": "A 3×3 Hill layer remains testable from aligned triples even though brute force is infeasible; structured reporting keeps it comparable with the rest of the strategy suite.",
        "category": "elimination",
    },
    "34": {
        "id": "34",
        "module": "strategy34_crib_dragging_toolkit",
        "slug": "crib-dragging-autocorrelation",
        "name": "Crib-Dragging Autocorrelation",
        "objective": "Expose lag, period, and autocorrelation signals from the standalone crib-dragging analysis through the toolkit.",
        "hypothesis": "Sliding the known anchors against K4 can reveal periodic or family-level structure without assuming a full decrypt model first.",
        "category": "analysis",
    },
    "35": {
        "id": "35",
        "module": "strategy35_pure_quagmire_toolkit",
        "slug": "pure-quagmire-deep-search",
        "name": "No-Transposition Quagmire III Deep Search",
        "objective": "Wrap the standalone pure-Quagmire search and compare its best outputs inside the toolkit.",
        "hypothesis": "If K4 is actually a direct Quagmire III variant with no transposition layer, an exhaustive keyword and offset sweep should surface anchor-consistent plaintext directly.",
        "category": "classical",
    },
    "36": {
        "id": "36",
        "module": "strategy36_anchor_sensitivity_toolkit",
        "slug": "anchor-position-sensitivity",
        "name": "Anchor Position Sensitivity Analysis",
        "objective": "Wrap the standalone shifted-anchor sweep and expose whether nearby anchor placements outperform the official clue coordinates.",
        "hypothesis": "If the public clue positions are slightly offset or interpreted too rigidly, shifted-anchor searches may admit better transposition-plus-key configurations than the original anchor layout.",
        "category": "analysis",
    },
    "37": {
        "id": "37",
        "module": "strategy37_transposition_unknown_source_running_key",
        "slug": "transposition-plus-unknown-source-running-key",
        "name": "Transposition + Unknown-Source Running Key",
        "objective": "Test bounded transposition candidates before decrypting with running-key windows drawn from the expanded unknown-source pool.",
        "hypothesis": "The strongest remaining compound hypothesis is that K4 uses both a transposition layer and a running key drawn from a non-obvious source text; combining those lanes directly may produce better global candidates than either lane alone.",
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
