from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import numpy as np

try:
    import pyopencl as cl
except ImportError:
    cl = None

from kryptos.benchmarking import build_benchmark_record, finalize_benchmark_record, get_benchmark_profile, list_profiles
from kryptos.common import analyze_layered_candidate, decrypt_bifid, extract_clue_hits, generate_polybius_square, mutate_polybius_square, preview_text
from kryptos.constants import DEFAULT_PERIODS, K4
from kryptos.dashboard import write_json
from kryptos.ledger import build_adaptive_guidance, load_ledger, merge_benchmark_into_ledger, write_ledger
from kryptos.paths import DEFAULT_DICTIONARY_PATH, resolve_repo_path


def load_dictionary(filepath: str) -> list[str]:
    path = resolve_repo_path(filepath)
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


KERNEL_CODE = """
inline int contains_term(__private const uchar* text, const int text_len, __private const uchar* term, const int term_len) {
    if (term_len > text_len) {
        return 0;
    }
    for (int start = 0; start <= text_len - term_len; ++start) {
        int matched = 1;
        for (int offset = 0; offset < term_len; ++offset) {
            if (text[start + offset] != term[offset]) {
                matched = 0;
                break;
            }
        }
        if (matched) {
            return 1;
        }
    }
    return 0;
}

inline uint hash_plaintext(__private const uchar* text, const int text_len) {
    uint hash = 2166136261u;
    for (int index = 0; index < text_len; ++index) {
        hash ^= (uint) text[index];
        hash *= 16777619u;
    }
    return hash;
}

inline int count_periodic_matches(__private const uchar* text, const int text_len, const int width) {
    int hits = 0;
    for (int index = 0; index < text_len - width; ++index) {
        if (text[index] == text[index + width]) {
            hits++;
        }
    }
    return hits;
}

inline int count_periodic_digrams(__private const uchar* text, const int text_len, const int width) {
    int hits = 0;
    for (int index = 0; index < text_len - width - 1; ++index) {
        if (text[index] == text[index + width] && text[index + 1] == text[index + width + 1]) {
            hits++;
        }
    }
    return hits;
}

__kernel void decrypt_bifid(
    __constant const uchar* k4,
    __global const uchar* base_squares,
    __constant const int* periods,
    const int num_periods,
    const int num_base_squares,
    const int copies_per_sweep,
    const int max_post_key_length,
    const int min_anchor_hits,
    __global int* candidate_gids,
    __global int* candidate_sweeps,
    __global int* candidate_scores,
    __global int* candidate_flags,
    __global uint* candidate_hashes,
    __global int* candidate_anchor_hits,
    __global int* candidate_context_hits,
    __global int* candidate_language_hints,
    __global int* candidate_ngram_hints,
    __global int* candidate_periodic_hints,
    __global int* candidate_displacement_hints,
    __global int* candidate_best_displacements,
    __global int* candidate_layer_hints,
    volatile __global int* candidate_count,
    volatile __global int* exact_match_count,
    const int candidate_limit,
    const int score_threshold,
    const int sweep_idx
) {
    int gid = get_global_id(0);

    int p_idx = gid % num_periods;
    int square_idx = gid / num_periods;

    int base_square_idx = square_idx % num_base_squares;
    int copy_idx = square_idx / num_base_squares;
    int mut_id = sweep_idx * copies_per_sweep + copy_idx;

    int period = periods[p_idx];
    __global const uchar* global_square = &base_squares[base_square_idx * 25];
    uchar local_square[25];
    for (int i = 0; i < 25; i++) {
        local_square[i] = global_square[i];
    }

    if (mut_id > 0) {
        ulong seed = mut_id * 19937 + 123456789;
        for (int s = 0; s < 4; s++) {
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
            int swap1 = seed % 25;
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
            int swap2 = seed % 25;
            uchar tmp = local_square[swap1];
            local_square[swap1] = local_square[swap2];
            local_square[swap2] = tmp;
        }
    }

    uchar r_map[26];
    uchar c_map[26];
    for (int i = 0; i < 26; i++) {
        r_map[i] = 255;
        c_map[i] = 255;
    }
    for (int sq = 0; sq < 25; ++sq) {
        int ch_idx = local_square[sq] - 'A';
        if (ch_idx >= 0 && ch_idx < 26) {
            r_map[ch_idx] = sq / 5;
            c_map[ch_idx] = sq % 5;
        }
    }

    uchar plaintext[97];

    for (int block_start = 0; block_start < 97; block_start += period) {
        int end = block_start + period;
        if (end > 97) {
            end = 97;
        }

        int block_len = end - block_start;
        uchar r[97];
        uchar c[97];
        int valid_len = 0;

        for (int i = 0; i < block_len; ++i) {
            uchar ch = k4[block_start + i];
            if (ch == 'J') {
                ch = 'I';
            }
            int ch_idx = ch - 'A';
            if (ch_idx >= 0 && ch_idx < 26) {
                uchar r_val = r_map[ch_idx];
                uchar c_val = c_map[ch_idx];
                if (r_val != 255) {
                    r[valid_len] = r_val;
                    c[valid_len] = c_val;
                    valid_len++;
                }
            }
        }

        uchar stream[194];
        for (int i = 0; i < valid_len; ++i) {
            stream[2 * i] = r[i];
            stream[2 * i + 1] = c[i];
        }

        for (int i = 0; i < valid_len; ++i) {
            int row_idx = stream[i];
            int col_idx = stream[valid_len + i];
            plaintext[block_start + i] = local_square[row_idx * 5 + col_idx];
        }
    }

    uchar east_combined[13] = {'E','A','S','T','N','O','R','T','H','E','A','S','T'};
    uchar berlin_combined[11] = {'B','E','R','L','I','N','C','L','O','C','K'};
    uchar east_component[4] = {'E','A','S','T'};
    uchar northeast_component[9] = {'N','O','R','T','H','E','A','S','T'};
    uchar berlin_component[6] = {'B','E','R','L','I','N'};
    uchar clock_component[5] = {'C','L','O','C','K'};
    uchar world_term[5] = {'W','O','R','L','D'};
    uchar message_term[7] = {'M','E','S','S','A','G','E'};
    uchar egypt_term[5] = {'E','G','Y','P','T'};
    uchar wall_term[4] = {'W','A','L','L'};
    uchar cia_term[3] = {'C','I','A'};
    uchar langley_term[7] = {'L','A','N','G','L','E','Y'};
    uchar tomb_term[4] = {'T','O','M','B'};
    uchar carry_term[5] = {'C','A','R','R','Y'};
    uchar send_term[4] = {'S','E','N','D'};
    uchar deliver_term[7] = {'D','E','L','I','V','E','R'};
    uchar the_term[3] = {'T','H','E'};
    uchar ing_term[3] = {'I','N','G'};
    uchar ion_term[3] = {'I','O','N'};
    uchar ent_term[3] = {'E','N','T'};
    uchar tion_term[4] = {'T','I','O','N'};
    uchar tio_term[3] = {'T','I','O'};
    uchar her_term[3] = {'H','E','R'};
    uchar ere_term[3] = {'E','R','E'};
    uchar tha_term[3] = {'T','H','A'};
    uchar ter_term[3] = {'T','E','R'};
    uchar ati_term[3] = {'A','T','I'};

    int score = 0;
    int exact_match = 0;
    int east_matches = 0;
    int berlin_matches = 0;
    int context_hits = 0;
    int language_hint = 0;
    int ngram_hint = 0;
    int periodic_hint = 0;
    int displacement_hint = 0;
    int best_displacement = 0;

    for (int i = 0; i < 13; ++i) {
        if (plaintext[21 + i] == east_combined[i]) {
            east_matches++;
            score += 180;
        }
        if (i < 12 && plaintext[21 + i] == east_combined[i] && plaintext[21 + i + 1] == east_combined[i + 1]) {
            score += 80;
        }
    }

    for (int i = 0; i < 11; ++i) {
        if (plaintext[63 + i] == berlin_combined[i]) {
            berlin_matches++;
            score += 180;
        }
        if (i < 10 && plaintext[63 + i] == berlin_combined[i] && plaintext[63 + i + 1] == berlin_combined[i + 1]) {
            score += 80;
        }
    }

    int anchor_hits = east_matches + berlin_matches;

    int east_exact = 1;
    for (int i = 0; i < 4; ++i) {
        if (plaintext[21 + i] != east_component[i]) {
            east_exact = 0;
        }
    }
    if (east_exact) {
        score += 900;
    }

    int northeast_exact = 1;
    for (int i = 0; i < 9; ++i) {
        if (plaintext[25 + i] != northeast_component[i]) {
            northeast_exact = 0;
        }
    }
    if (northeast_exact) {
        score += 1400;
    }

    int berlin_exact = 1;
    for (int i = 0; i < 6; ++i) {
        if (plaintext[63 + i] != berlin_component[i]) {
            berlin_exact = 0;
        }
    }
    if (berlin_exact) {
        score += 1200;
    }

    int clock_exact = 1;
    for (int i = 0; i < 5; ++i) {
        if (plaintext[69 + i] != clock_component[i]) {
            clock_exact = 0;
        }
    }
    if (clock_exact) {
        score += 1100;
    }

    if (east_matches == 13) {
        score += 3500;
        exact_match = 1;
    }
    if (berlin_matches == 11) {
        score += 3000;
        exact_match = 1;
    }

    if (contains_term(plaintext, 97, east_component, 4)) {
        score += 140;
    }
    if (contains_term(plaintext, 97, northeast_component, 9)) {
        score += 220;
    }
    if (contains_term(plaintext, 97, berlin_component, 6)) {
        score += 180;
    }
    if (contains_term(plaintext, 97, clock_component, 5)) {
        score += 180;
    }

    if (contains_term(plaintext, 97, east_combined, 13)) {
        score += 20000;
        exact_match = 1;
    }
    if (contains_term(plaintext, 97, berlin_combined, 11)) {
        score += 18000;
        exact_match = 1;
    }

    if (contains_term(plaintext, 97, world_term, 5)) {
        score += 180;
        context_hits++;
    }
    if (contains_term(plaintext, 97, message_term, 7)) {
        score += 180;
        context_hits++;
    }
    if (contains_term(plaintext, 97, egypt_term, 5)) {
        score += 150;
        context_hits++;
    }
    if (contains_term(plaintext, 97, wall_term, 4)) {
        score += 120;
        context_hits++;
    }
    if (contains_term(plaintext, 97, cia_term, 3)) {
        score += 90;
        context_hits++;
    }
    if (contains_term(plaintext, 97, langley_term, 7)) {
        score += 150;
        context_hits++;
    }
    if (contains_term(plaintext, 97, tomb_term, 4)) {
        score += 120;
        context_hits++;
    }
    if (contains_term(plaintext, 97, carry_term, 5)) {
        score += 100;
        context_hits++;
    }
    if (contains_term(plaintext, 97, send_term, 4)) {
        score += 100;
        context_hits++;
    }
    if (contains_term(plaintext, 97, deliver_term, 7)) {
        score += 150;
        context_hits++;
    }

    int vowel_count = 0;
    int harsh_count = 0;
    for (int i = 0; i < 97; ++i) {
        uchar ch = plaintext[i];
        if (ch == 'A' || ch == 'E' || ch == 'I' || ch == 'O' || ch == 'U' || ch == 'Y') {
            vowel_count++;
        }
        if (ch == 'Q' || ch == 'Z' || ch == 'X' || ch == 'J') {
            harsh_count++;
        }
    }

    int vowel_pct = vowel_count * 100;
    if (vowel_pct >= 24 * 97 && vowel_pct <= 48 * 97) {
        score += 220;
        language_hint += 220;
    } else if (vowel_pct >= 18 * 97 && vowel_pct <= 55 * 97) {
        score += 90;
        language_hint += 90;
    }
    if (harsh_count * 100 <= 14 * 97) {
        score += 120;
        language_hint += 120;
    }
    if (contains_term(plaintext, 97, the_term, 3)) {
        ngram_hint += 80;
    }
    if (contains_term(plaintext, 97, ing_term, 3)) {
        ngram_hint += 60;
    }
    if (contains_term(plaintext, 97, ion_term, 3)) {
        ngram_hint += 60;
    }
    if (contains_term(plaintext, 97, ent_term, 3)) {
        ngram_hint += 60;
    }
    if (contains_term(plaintext, 97, tion_term, 4)) {
        ngram_hint += 90;
    }
    if (contains_term(plaintext, 97, tio_term, 3)) {
        ngram_hint += 55;
    }
    if (contains_term(plaintext, 97, her_term, 3)) {
        ngram_hint += 55;
    }
    if (contains_term(plaintext, 97, ere_term, 3)) {
        ngram_hint += 55;
    }
    if (contains_term(plaintext, 97, tha_term, 3)) {
        ngram_hint += 55;
    }
    if (contains_term(plaintext, 97, ter_term, 3)) {
        ngram_hint += 55;
    }
    if (contains_term(plaintext, 97, ati_term, 3)) {
        ngram_hint += 55;
    }

    int periodic_widths[4] = {5, 7, 9, 12};
    for (int width_index = 0; width_index < 4; ++width_index) {
        int width = periodic_widths[width_index];
        int single_matches = count_periodic_matches(plaintext, 97, width);
        if (single_matches >= 4) {
            periodic_hint += min(single_matches * 14, 140);
        }

        int digram_matches = count_periodic_digrams(plaintext, 97, width);
        if (digram_matches > 0) {
            periodic_hint += min(digram_matches * 45, 180);
        }
    }

    int best_displacement_score = 0;
    int best_displacement_matches = 0;
    int best_displacement_exacts = 0;
    for (int delta = -24; delta <= 24; ++delta) {
        if (delta == 0) {
            continue;
        }

        int displacement_matches = 0;
        int exact_components = 0;

        int east_pos = 21 + delta;
        if (east_pos >= 0 && east_pos + 4 <= 97) {
            int component_matches = 0;
            for (int i = 0; i < 4; ++i) {
                if (plaintext[east_pos + i] == east_component[i]) {
                    displacement_matches++;
                    component_matches++;
                }
            }
            if (component_matches == 4) {
                exact_components++;
            }
        }

        int northeast_pos = 25 + delta;
        if (northeast_pos >= 0 && northeast_pos + 9 <= 97) {
            int component_matches = 0;
            for (int i = 0; i < 9; ++i) {
                if (plaintext[northeast_pos + i] == northeast_component[i]) {
                    displacement_matches++;
                    component_matches++;
                }
            }
            if (component_matches == 9) {
                exact_components++;
            }
        }

        int berlin_pos = 63 + delta;
        if (berlin_pos >= 0 && berlin_pos + 6 <= 97) {
            int component_matches = 0;
            for (int i = 0; i < 6; ++i) {
                if (plaintext[berlin_pos + i] == berlin_component[i]) {
                    displacement_matches++;
                    component_matches++;
                }
            }
            if (component_matches == 6) {
                exact_components++;
            }
        }

        int clock_pos = 69 + delta;
        if (clock_pos >= 0 && clock_pos + 5 <= 97) {
            int component_matches = 0;
            for (int i = 0; i < 5; ++i) {
                if (plaintext[clock_pos + i] == clock_component[i]) {
                    displacement_matches++;
                    component_matches++;
                }
            }
            if (component_matches == 5) {
                exact_components++;
            }
        }

        int displacement_score = displacement_matches * 26 + exact_components * 150;
        if (delta >= -6 && delta <= 6) {
            displacement_score += 45;
        } else if (delta >= -12 && delta <= 12) {
            displacement_score += 25;
        } else {
            displacement_score += 10;
        }

        if (displacement_score > best_displacement_score) {
            best_displacement_score = displacement_score;
            best_displacement_matches = displacement_matches;
            best_displacement_exacts = exact_components;
            best_displacement = delta;
        }
    }

    if (best_displacement_matches >= 5) {
        displacement_hint = min(best_displacement_score, 520);
        if (best_displacement_exacts >= 2) {
            displacement_hint = min(displacement_hint + 40, 560);
        }
    } else {
        best_displacement = 0;
    }

    int best_layer_hint = 0;
    for (int key_len = 1; key_len <= max_post_key_length; ++key_len) {
        uchar assigned[12];
        uchar shifts[12];
        for (int i = 0; i < 12; ++i) {
            assigned[i] = 0;
            shifts[i] = 0;
        }

        int coverage = 0;
        int consistent = 1;

        for (int i = 0; i < 13 && consistent; ++i) {
            int residue = (21 + i) % key_len;
            int shift = ((int) plaintext[21 + i] - (int) east_combined[i] + 26) % 26;
            if (!assigned[residue]) {
                assigned[residue] = 1;
                shifts[residue] = (uchar) shift;
                coverage++;
            } else if ((int) shifts[residue] != shift) {
                consistent = 0;
            }
        }

        for (int i = 0; i < 11 && consistent; ++i) {
            int residue = (63 + i) % key_len;
            int shift = ((int) plaintext[63 + i] - (int) berlin_combined[i] + 26) % 26;
            if (!assigned[residue]) {
                assigned[residue] = 1;
                shifts[residue] = (uchar) shift;
                coverage++;
            } else if ((int) shifts[residue] != shift) {
                consistent = 0;
            }
        }

        if (consistent && coverage == key_len) {
            int layer_score = 1500 - (key_len * 40);
            if (layer_score > best_layer_hint) {
                best_layer_hint = layer_score;
            }
        }
    }

    score += best_layer_hint;
    uint plaintext_hash = hash_plaintext(plaintext, 97);

    if (exact_match) {
        atomic_add(exact_match_count, 1);
    }

    int eligible = exact_match || (anchor_hits >= min_anchor_hits && score >= score_threshold);
    if (eligible) {
        int idx = atomic_add(candidate_count, 1);
        if (idx < candidate_limit) {
            candidate_gids[idx] = gid;
            candidate_sweeps[idx] = sweep_idx;
            candidate_scores[idx] = score;
            candidate_flags[idx] = exact_match;
            candidate_hashes[idx] = plaintext_hash;
            candidate_anchor_hits[idx] = anchor_hits;
            candidate_context_hits[idx] = context_hits;
            candidate_language_hints[idx] = language_hint;
            candidate_ngram_hints[idx] = ngram_hint;
            candidate_periodic_hints[idx] = periodic_hint;
            candidate_displacement_hints[idx] = displacement_hint;
            candidate_best_displacements[idx] = best_displacement;
            candidate_layer_hints[idx] = best_layer_hint;
        }
    }
}
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the OpenCL Bifid sweep against the K4 dictionary.")
    parser.add_argument("--profile", choices=list_profiles("gpu-opencl"), default="default", help="Benchmark profile to apply before explicit overrides.")
    parser.add_argument("--dictionary", default=str(DEFAULT_DICTIONARY_PATH), help="Dictionary file to load.")
    parser.add_argument("--passes", type=int, help="Number of passes to run unless --continuous is set.")
    parser.add_argument("--continuous", action="store_true", help="Keep running passes until interrupted.")
    parser.add_argument("--sweeps-per-pass", type=int, help="Kernel sweeps to launch per pass.")
    parser.add_argument("--copies-per-sweep", type=int, help="Mutated square copies to test per dictionary word.")
    parser.add_argument("--match-limit", type=int, help="Maximum number of raw GPU candidates to collect per pass.")
    parser.add_argument("--score-threshold", type=int, help="Minimum kernel score required to retain a candidate for CPU analysis.")
    parser.add_argument("--top-candidates", type=int, help="Number of hydrated candidates to surface after CPU-side analysis.")
    parser.add_argument("--hydrate-limit", type=int, help="Maximum number of raw GPU candidates to hydrate on the CPU per pass.")
    parser.add_argument("--min-anchor-hits", type=int, help="Minimum anchor-position character matches required before hydration.")
    parser.add_argument("--max-post-key-length", type=int, help="Longest repeating Vigenere layer to infer from the clue anchors.")
    parser.add_argument("--ledger-input", help="Load adaptive hydration guidance from an existing research ledger JSON file.")
    parser.add_argument("--json", action="store_true", help="Emit the final summary as JSON.")
    parser.add_argument("--output", help="Write the final summary to a JSON file.")
    parser.add_argument("--ledger-output", help="Merge hydrated GPU candidates into a persistent research ledger JSON file.")
    return parser.parse_args()


def _adaptive_budget_bonus(guidance: dict[str, Any], family: str, *, max_extra: int = 4) -> int:
    preferred = [str(value) for value in guidance.get("preferred_stage_families") or []]
    if family not in preferred:
        return 0
    return max(0, max_extra - preferred.index(family))


def load_adaptive_guidance(args: argparse.Namespace) -> dict[str, Any]:
    ledger_path = args.ledger_input or args.ledger_output
    if not ledger_path:
        return {}
    return build_adaptive_guidance(load_ledger(ledger_path))


def resolve_profile_config(args: argparse.Namespace, adaptive_guidance: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = get_benchmark_profile("gpu-opencl", args.profile)
    config = {
        "passes": args.passes if args.passes is not None else profile["passes"],
        "sweeps_per_pass": args.sweeps_per_pass if args.sweeps_per_pass is not None else profile["sweeps_per_pass"],
        "copies_per_sweep": args.copies_per_sweep if args.copies_per_sweep is not None else profile["copies_per_sweep"],
        "match_limit": args.match_limit if args.match_limit is not None else profile["match_limit"],
        "score_threshold": args.score_threshold if args.score_threshold is not None else int(profile.get("score_threshold", 1300)),
        "top_candidate_limit": args.top_candidates if args.top_candidates is not None else int(profile.get("top_candidate_limit", 10)),
        "hydrate_limit": args.hydrate_limit if args.hydrate_limit is not None else int(profile.get("hydrate_limit", 32)),
        "min_anchor_hits": args.min_anchor_hits if args.min_anchor_hits is not None else int(profile.get("min_anchor_hits", 1)),
        "max_post_key_length": args.max_post_key_length if args.max_post_key_length is not None else int(profile.get("max_post_key_length", 12)),
    }
    adaptive_guidance = adaptive_guidance or {}
    if adaptive_guidance.get("enabled"):
        periodic_bonus = _adaptive_budget_bonus(adaptive_guidance, "periodic_transposition", max_extra=3)
        layer_bonus = _adaptive_budget_bonus(adaptive_guidance, "key-layer", max_extra=3)
        bifid_bonus = _adaptive_budget_bonus(adaptive_guidance, "bifid", max_extra=3)
        config["hydrate_limit"] += periodic_bonus + layer_bonus
        config["top_candidate_limit"] += max(periodic_bonus, layer_bonus)
        config["score_threshold"] = max(0, config["score_threshold"] - (bifid_bonus * 40))
        config["adaptive_hydrate_bonus"] = periodic_bonus + layer_bonus
        config["adaptive_top_candidate_bonus"] = max(periodic_bonus, layer_bonus)
        config["adaptive_threshold_delta"] = bifid_bonus * 40
    else:
        config["adaptive_hydrate_bonus"] = 0
        config["adaptive_top_candidate_bonus"] = 0
        config["adaptive_threshold_delta"] = 0
    config["max_post_key_length"] = min(max(config["max_post_key_length"], 1), 12)
    config["top_candidate_limit"] = min(max(config["top_candidate_limit"], 1), config["match_limit"])
    config["hydrate_limit"] = min(max(config["hydrate_limit"], config["top_candidate_limit"]), config["match_limit"])
    config["min_anchor_hits"] = min(max(config["min_anchor_hits"], 1), 24)
    return config


def select_device() -> Any:
    if cl is None:
        raise RuntimeError("PyOpenCL is not installed. Run 'pip install pyopencl'.")
    platforms = cl.get_platforms()
    if not platforms:
        raise RuntimeError("No OpenCL platforms found.")
    for platform in platforms:
        for device in platform.get_devices():
            if device.type == cl.device_type.GPU:
                return device
    return platforms[0].get_devices()[0]


def reset_pass_buffers(
    queue: Any,
    candidate_count_buffer: Any,
    candidate_count_np: np.ndarray,
    exact_match_count_buffer: Any,
    exact_match_count_np: np.ndarray,
    candidate_gids_buffer: Any,
    candidate_gids_np: np.ndarray,
    candidate_sweeps_buffer: Any,
    candidate_sweeps_np: np.ndarray,
    candidate_scores_buffer: Any,
    candidate_scores_np: np.ndarray,
    candidate_flags_buffer: Any,
    candidate_flags_np: np.ndarray,
    candidate_hashes_buffer: Any,
    candidate_hashes_np: np.ndarray,
    candidate_anchor_hits_buffer: Any,
    candidate_anchor_hits_np: np.ndarray,
    candidate_context_hits_buffer: Any,
    candidate_context_hits_np: np.ndarray,
    candidate_language_hints_buffer: Any,
    candidate_language_hints_np: np.ndarray,
    candidate_ngram_hints_buffer: Any,
    candidate_ngram_hints_np: np.ndarray,
    candidate_periodic_hints_buffer: Any,
    candidate_periodic_hints_np: np.ndarray,
    candidate_displacement_hints_buffer: Any,
    candidate_displacement_hints_np: np.ndarray,
    candidate_best_displacements_buffer: Any,
    candidate_best_displacements_np: np.ndarray,
    candidate_layer_hints_buffer: Any,
    candidate_layer_hints_np: np.ndarray,
) -> None:
    candidate_count_np.fill(0)
    exact_match_count_np.fill(0)
    candidate_gids_np.fill(-1)
    candidate_sweeps_np.fill(-1)
    candidate_scores_np.fill(0)
    candidate_flags_np.fill(0)
    candidate_hashes_np.fill(0)
    candidate_anchor_hits_np.fill(0)
    candidate_context_hits_np.fill(0)
    candidate_language_hints_np.fill(0)
    candidate_ngram_hints_np.fill(0)
    candidate_periodic_hints_np.fill(0)
    candidate_displacement_hints_np.fill(0)
    candidate_best_displacements_np.fill(0)
    candidate_layer_hints_np.fill(0)
    cl.enqueue_copy(queue, candidate_count_buffer, candidate_count_np).wait()
    cl.enqueue_copy(queue, exact_match_count_buffer, exact_match_count_np).wait()
    cl.enqueue_copy(queue, candidate_gids_buffer, candidate_gids_np).wait()
    cl.enqueue_copy(queue, candidate_sweeps_buffer, candidate_sweeps_np).wait()
    cl.enqueue_copy(queue, candidate_scores_buffer, candidate_scores_np).wait()
    cl.enqueue_copy(queue, candidate_flags_buffer, candidate_flags_np).wait()
    cl.enqueue_copy(queue, candidate_hashes_buffer, candidate_hashes_np).wait()
    cl.enqueue_copy(queue, candidate_anchor_hits_buffer, candidate_anchor_hits_np).wait()
    cl.enqueue_copy(queue, candidate_context_hits_buffer, candidate_context_hits_np).wait()
    cl.enqueue_copy(queue, candidate_language_hints_buffer, candidate_language_hints_np).wait()
    cl.enqueue_copy(queue, candidate_ngram_hints_buffer, candidate_ngram_hints_np).wait()
    cl.enqueue_copy(queue, candidate_periodic_hints_buffer, candidate_periodic_hints_np).wait()
    cl.enqueue_copy(queue, candidate_displacement_hints_buffer, candidate_displacement_hints_np).wait()
    cl.enqueue_copy(queue, candidate_best_displacements_buffer, candidate_best_displacements_np).wait()
    cl.enqueue_copy(queue, candidate_layer_hints_buffer, candidate_layer_hints_np).wait()


def serialize_device(device: Any) -> dict[str, str | int]:
    return {
        "name": device.name,
        "vendor": device.vendor,
        "version": device.version,
        "driver_version": device.driver_version,
        "type": cl.device_type.to_string(device.type),
        "compute_units": device.max_compute_units,
        "global_memory_bytes": int(device.global_mem_size),
    }


def decode_candidate_identity(
    raw_gid: int,
    sweep_index: int,
    *,
    num_periods: int,
    num_base_squares: int,
    copies_per_sweep: int,
) -> dict[str, int]:
    period_index = raw_gid % num_periods
    square_index = raw_gid // num_periods
    base_square_index = square_index % num_base_squares
    copy_index = square_index // num_base_squares
    mutation_id = sweep_index * copies_per_sweep + copy_index
    return {
        "period_index": period_index,
        "period": int(DEFAULT_PERIODS[period_index]),
        "base_square_index": base_square_index,
        "copy_index": copy_index,
        "mutation_id": mutation_id,
    }


def build_raw_candidate_entry(
    *,
    raw_gid: int,
    sweep_index: int,
    raw_score: int,
    exact_match: bool,
    plaintext_hash: int,
    anchor_hits: int,
    context_hits: int,
    language_hint: int,
    ngram_hint: int,
    periodic_hint: int,
    displacement_hint: int,
    best_displacement: int,
    layer_hint: int,
) -> dict[str, int | bool]:
    return {
        "raw_gid": int(raw_gid),
        "sweep_index": int(sweep_index),
        "raw_score": int(raw_score),
        "exact_match": bool(exact_match),
        "plaintext_hash": int(plaintext_hash),
        "anchor_hits": int(anchor_hits),
        "context_hits": int(context_hits),
        "language_hint": int(language_hint),
        "ngram_hint": int(ngram_hint),
        "periodic_hint": int(periodic_hint),
        "displacement_hint": int(displacement_hint),
        "best_displacement": int(best_displacement),
        "layer_hint": int(layer_hint),
    }


def sort_raw_candidate_entries(entries: list[dict[str, int | bool]]) -> list[dict[str, int | bool]]:
    return sorted(
        entries,
        key=lambda entry: (
            int(bool(entry["exact_match"])),
            int(entry["raw_score"]),
            int(entry.get("displacement_hint", 0)),
            int(entry.get("periodic_hint", 0)),
            int(entry.get("ngram_hint", 0)),
            int(entry["anchor_hits"]),
            int(entry["context_hits"]),
            int(entry["language_hint"]),
            int(entry["layer_hint"]),
        ),
        reverse=True,
    )


def select_candidates_for_hydration(
    entries: list[dict[str, int | bool]],
    hydrate_limit: int,
) -> list[dict[str, int | bool]]:
    selected: list[dict[str, int | bool]] = []
    seen_signatures: set[tuple[int, int, int, int]] = set()
    for entry in sort_raw_candidate_entries(entries):
        signature = (
            int(entry["plaintext_hash"]),
            int(entry["anchor_hits"]),
            int(entry["context_hits"]),
            int(entry["language_hint"]),
        )
        if signature in seen_signatures:
            continue
        selected.append(entry)
        seen_signatures.add(signature)
        if len(selected) >= hydrate_limit:
            break
    return selected


def build_candidate_record(
    raw_candidate: dict[str, int | bool],
    *,
    words: list[str],
    base_squares: list[str],
    num_periods: int,
    num_base_squares: int,
    copies_per_sweep: int,
    max_post_key_length: int,
) -> dict[str, object]:
    identity = decode_candidate_identity(
        int(raw_candidate["raw_gid"]),
        int(raw_candidate["sweep_index"]),
        num_periods=num_periods,
        num_base_squares=num_base_squares,
        copies_per_sweep=copies_per_sweep,
    )
    keyword = words[identity["base_square_index"]]
    square = mutate_polybius_square(base_squares[identity["base_square_index"]], identity["mutation_id"])
    direct_plaintext = decrypt_bifid(identity["period"], K4, square)
    layered = analyze_layered_candidate(direct_plaintext, max_key_length=max_post_key_length)
    transform_chain = [f"bifid:{keyword}:period={identity['period']}", *list(layered["transform_chain"])]
    key_material = {
        "stage1": {
            "keyword": keyword,
            "period": identity["period"],
            "mutation_id": identity["mutation_id"],
        },
        "stage2": dict(layered["key_material"]),
    }
    return {
        "raw_gid": int(raw_candidate["raw_gid"]),
        "raw_score": int(raw_candidate["raw_score"]),
        "exact_match": bool(raw_candidate["exact_match"]),
        "plaintext_hash": int(raw_candidate["plaintext_hash"]),
        "raw_anchor_hits": int(raw_candidate["anchor_hits"]),
        "raw_context_hits": int(raw_candidate["context_hits"]),
        "raw_language_hint": int(raw_candidate["language_hint"]),
        "raw_ngram_hint": int(raw_candidate.get("ngram_hint", 0)),
        "raw_periodic_hint": int(raw_candidate.get("periodic_hint", 0)),
        "raw_displacement_hint": int(raw_candidate.get("displacement_hint", 0)),
        "raw_best_displacement": int(raw_candidate.get("best_displacement", 0)),
        "raw_layer_hint": int(raw_candidate["layer_hint"]),
        "keyword": keyword,
        "period": identity["period"],
        "mutation_id": identity["mutation_id"],
        "sweep_index": int(raw_candidate["sweep_index"]),
        "direct_preview": preview_text(direct_plaintext),
        "direct_clue_hits": extract_clue_hits(direct_plaintext),
        "best_mode": layered["mode"],
        "best_score": layered["score"],
        "total_score": layered["score"],
        "derived_key": layered["derived_key"],
        "key_length": layered["key_length"],
        "matched_clues": layered["matched_clues"],
        "plaintext": layered["plaintext"],
        "best_preview": layered["preview"],
        "preview": layered["preview"],
        "breakdown": layered["breakdown"],
        "transform_chain": transform_chain,
        "key_material": key_material,
    }


def sort_candidate_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        records,
        key=lambda record: (
            int(bool(record["exact_match"])),
            len(record["matched_clues"]),
            int(record["best_score"]),
            int(record.get("raw_displacement_hint", 0)),
            int(record.get("raw_periodic_hint", 0)),
            int(record.get("raw_ngram_hint", 0)),
            int(record["raw_anchor_hits"]),
            int(record["raw_context_hits"]),
            int(record["raw_score"]),
        ),
        reverse=True,
    )


def run_benchmark(args: argparse.Namespace | None = None) -> dict[str, object]:
    args = args or parse_args()
    adaptive_guidance = load_adaptive_guidance(args)
    config = resolve_profile_config(args, adaptive_guidance=adaptive_guidance)
    started = time.time()
    device = select_device()
    ctx = cl.Context([device])
    queue = cl.CommandQueue(ctx)
    program = cl.Program(ctx, KERNEL_CODE).build()

    k4_bytes = np.array([ord(char) for char in K4], dtype=np.uint8)
    mem_flags = cl.mem_flags
    k4_buffer = cl.Buffer(ctx, mem_flags.READ_ONLY | mem_flags.COPY_HOST_PTR, hostbuf=k4_bytes)

    words = load_dictionary(args.dictionary)
    base_squares = [generate_polybius_square(word) for word in words]
    squares_bytes = b"".join(square.encode("ascii") for square in base_squares)
    squares_np = np.frombuffer(squares_bytes, dtype=np.uint8)
    squares_buffer = cl.Buffer(ctx, mem_flags.READ_ONLY | mem_flags.COPY_HOST_PTR, hostbuf=squares_np)

    periods = np.array(DEFAULT_PERIODS, dtype=np.int32)
    periods_buffer = cl.Buffer(ctx, mem_flags.READ_ONLY | mem_flags.COPY_HOST_PTR, hostbuf=periods)
    num_periods = len(periods)
    num_base_squares = len(base_squares)
    total_work_items = num_base_squares * config["copies_per_sweep"] * num_periods

    candidate_gids_np = np.full(config["match_limit"], -1, dtype=np.int32)
    candidate_gids_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_gids_np)
    candidate_sweeps_np = np.full(config["match_limit"], -1, dtype=np.int32)
    candidate_sweeps_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_sweeps_np)
    candidate_scores_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_scores_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_scores_np)
    candidate_flags_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_flags_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_flags_np)
    candidate_hashes_np = np.zeros(config["match_limit"], dtype=np.uint32)
    candidate_hashes_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_hashes_np)
    candidate_anchor_hits_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_anchor_hits_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_anchor_hits_np)
    candidate_context_hits_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_context_hits_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_context_hits_np)
    candidate_language_hints_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_language_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_language_hints_np)
    candidate_ngram_hints_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_ngram_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_ngram_hints_np)
    candidate_periodic_hints_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_periodic_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_periodic_hints_np)
    candidate_displacement_hints_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_displacement_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_displacement_hints_np)
    candidate_best_displacements_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_best_displacements_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_best_displacements_np)
    candidate_layer_hints_np = np.zeros(config["match_limit"], dtype=np.int32)
    candidate_layer_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_layer_hints_np)
    candidate_count_np = np.zeros(1, dtype=np.int32)
    candidate_count_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_count_np)
    exact_match_count_np = np.zeros(1, dtype=np.int32)
    exact_match_count_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=exact_match_count_np)

    decrypt_kernel = cl.Kernel(program, "decrypt_bifid")
    pass_summaries: list[dict[str, object]] = []
    overall_candidates: list[dict[str, object]] = []
    total_decryptions = 0
    total_qualified_candidates = 0
    total_hydrated_candidates = 0
    pass_number = 1
    benchmark_record = build_benchmark_record(
        "gpu-opencl",
        args.profile,
        {
            **config,
            "dictionary": str(resolve_repo_path(args.dictionary)),
            "periods": list(DEFAULT_PERIODS),
            "continuous": args.continuous,
            "adaptive_guidance_enabled": bool(adaptive_guidance.get("enabled")),
        },
        command=sys.argv,
    )

    try:
        while args.continuous or pass_number <= config["passes"]:
            pass_started = time.time()
            reset_pass_buffers(
                queue,
                candidate_count_buffer,
                candidate_count_np,
                exact_match_count_buffer,
                exact_match_count_np,
                candidate_gids_buffer,
                candidate_gids_np,
                candidate_sweeps_buffer,
                candidate_sweeps_np,
                candidate_scores_buffer,
                candidate_scores_np,
                candidate_flags_buffer,
                candidate_flags_np,
                candidate_hashes_buffer,
                candidate_hashes_np,
                candidate_anchor_hits_buffer,
                candidate_anchor_hits_np,
                candidate_context_hits_buffer,
                candidate_context_hits_np,
                candidate_language_hints_buffer,
                candidate_language_hints_np,
                candidate_ngram_hints_buffer,
                candidate_ngram_hints_np,
                candidate_periodic_hints_buffer,
                candidate_periodic_hints_np,
                candidate_displacement_hints_buffer,
                candidate_displacement_hints_np,
                candidate_best_displacements_buffer,
                candidate_best_displacements_np,
                candidate_layer_hints_buffer,
                candidate_layer_hints_np,
            )
            pass_decryptions = 0
            sweep_offset = (pass_number - 1) * config["sweeps_per_pass"]

            for sweep in range(config["sweeps_per_pass"]):
                decrypt_kernel(
                    queue,
                    (total_work_items,),
                    None,
                    k4_buffer,
                    squares_buffer,
                    periods_buffer,
                    np.int32(num_periods),
                    np.int32(num_base_squares),
                    np.int32(config["copies_per_sweep"]),
                    np.int32(config["max_post_key_length"]),
                    np.int32(config["min_anchor_hits"]),
                    candidate_gids_buffer,
                    candidate_sweeps_buffer,
                    candidate_scores_buffer,
                    candidate_flags_buffer,
                    candidate_hashes_buffer,
                    candidate_anchor_hits_buffer,
                    candidate_context_hits_buffer,
                    candidate_language_hints_buffer,
                    candidate_ngram_hints_buffer,
                    candidate_periodic_hints_buffer,
                    candidate_displacement_hints_buffer,
                    candidate_best_displacements_buffer,
                    candidate_layer_hints_buffer,
                    candidate_count_buffer,
                    exact_match_count_buffer,
                    np.int32(config["match_limit"]),
                    np.int32(config["score_threshold"]),
                    np.int32(sweep_offset + sweep),
                )
                queue.finish()
                pass_decryptions += total_work_items

            cl.enqueue_copy(queue, candidate_count_np, candidate_count_buffer).wait()
            cl.enqueue_copy(queue, exact_match_count_np, exact_match_count_buffer).wait()
            pass_candidate_count = int(candidate_count_np[0])
            pass_exact_match_count = int(exact_match_count_np[0])
            total_qualified_candidates += pass_candidate_count
            stored_candidate_count = min(pass_candidate_count, config["match_limit"])
            hydrated_candidate_count = 0
            pass_candidates: list[dict[str, object]] = []

            if stored_candidate_count > 0:
                cl.enqueue_copy(queue, candidate_gids_np, candidate_gids_buffer).wait()
                cl.enqueue_copy(queue, candidate_sweeps_np, candidate_sweeps_buffer).wait()
                cl.enqueue_copy(queue, candidate_scores_np, candidate_scores_buffer).wait()
                cl.enqueue_copy(queue, candidate_flags_np, candidate_flags_buffer).wait()
                cl.enqueue_copy(queue, candidate_hashes_np, candidate_hashes_buffer).wait()
                cl.enqueue_copy(queue, candidate_anchor_hits_np, candidate_anchor_hits_buffer).wait()
                cl.enqueue_copy(queue, candidate_context_hits_np, candidate_context_hits_buffer).wait()
                cl.enqueue_copy(queue, candidate_language_hints_np, candidate_language_hints_buffer).wait()
                cl.enqueue_copy(queue, candidate_ngram_hints_np, candidate_ngram_hints_buffer).wait()
                cl.enqueue_copy(queue, candidate_periodic_hints_np, candidate_periodic_hints_buffer).wait()
                cl.enqueue_copy(queue, candidate_displacement_hints_np, candidate_displacement_hints_buffer).wait()
                cl.enqueue_copy(queue, candidate_best_displacements_np, candidate_best_displacements_buffer).wait()
                cl.enqueue_copy(queue, candidate_layer_hints_np, candidate_layer_hints_buffer).wait()
                raw_candidates = [
                    build_raw_candidate_entry(
                        raw_gid=int(candidate_gids_np[index]),
                        sweep_index=int(candidate_sweeps_np[index]),
                        raw_score=int(candidate_scores_np[index]),
                        exact_match=bool(candidate_flags_np[index]),
                        plaintext_hash=int(candidate_hashes_np[index]),
                        anchor_hits=int(candidate_anchor_hits_np[index]),
                        context_hits=int(candidate_context_hits_np[index]),
                        language_hint=int(candidate_language_hints_np[index]),
                        ngram_hint=int(candidate_ngram_hints_np[index]),
                        periodic_hint=int(candidate_periodic_hints_np[index]),
                        displacement_hint=int(candidate_displacement_hints_np[index]),
                        best_displacement=int(candidate_best_displacements_np[index]),
                        layer_hint=int(candidate_layer_hints_np[index]),
                    )
                    for index in range(stored_candidate_count)
                ]
                selected_candidates = select_candidates_for_hydration(raw_candidates, config["hydrate_limit"])
                hydrated_candidate_count = len(selected_candidates)
                total_hydrated_candidates += hydrated_candidate_count
                for raw_candidate in selected_candidates:
                    pass_candidates.append(
                        build_candidate_record(
                            raw_candidate,
                            words=words,
                            base_squares=base_squares,
                            num_periods=num_periods,
                            num_base_squares=num_base_squares,
                            copies_per_sweep=config["copies_per_sweep"],
                            max_post_key_length=config["max_post_key_length"],
                        )
                    )
                pass_candidates = sort_candidate_records(pass_candidates)
                overall_candidates.extend(pass_candidates)

            elapsed = round(time.time() - pass_started, 6)
            total_decryptions += pass_decryptions
            pass_summaries.append(
                {
                    "pass_number": pass_number,
                    "attempts": pass_decryptions,
                    "unique_attempts": pass_decryptions,
                    "attempts_per_second": round(pass_decryptions / elapsed, 6) if elapsed > 0 else 0.0,
                    "match_count": pass_exact_match_count,
                    "qualified_candidate_count": pass_candidate_count,
                    "stored_candidate_count": stored_candidate_count,
                    "hydrated_candidate_count": hydrated_candidate_count,
                    "top_candidates": pass_candidates[: config["top_candidate_limit"]],
                    "elapsed_seconds": elapsed,
                }
            )

            if not args.json:
                print(
                    f"Pass {pass_number}: attempts={pass_decryptions:,}, "
                    f"exact_matches={pass_exact_match_count}, candidates={pass_candidate_count}, hydrated={hydrated_candidate_count}, elapsed={elapsed:.4f}s"
                )

            pass_number += 1
    except KeyboardInterrupt:
        if not args.json:
            print("Sweep interrupted by user.")

    overall_top_candidates = sort_candidate_records(overall_candidates)[: config["top_candidate_limit"]]
    summary = finalize_benchmark_record(
        benchmark_record,
        attempts=total_decryptions,
        unique_attempts=total_decryptions,
        elapsed_seconds=time.time() - started,
        match_count=sum(int(pass_summary["match_count"]) for pass_summary in pass_summaries),
        pass_summaries=pass_summaries,
        hardware=serialize_device(device),
        artifacts={
            "dictionary_path": str(resolve_repo_path(args.dictionary)),
            "dictionary_words": len(words),
            "periods": list(DEFAULT_PERIODS),
            "passes_completed": len(pass_summaries),
            "score_threshold": config["score_threshold"],
            "hydrate_limit": config["hydrate_limit"],
            "min_anchor_hits": config["min_anchor_hits"],
            "qualified_candidate_count": total_qualified_candidates,
            "hydrated_candidate_count": total_hydrated_candidates,
            "top_candidates": overall_top_candidates,
        },
    )

    return summary


def main() -> None:
    args = parse_args()
    try:
        summary = run_benchmark(args)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    if args.output:
        write_json(args.output, summary)
    if args.ledger_output:
        ledger = merge_benchmark_into_ledger(load_ledger(args.ledger_output), summary)
        write_ledger(args.ledger_output, ledger)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
