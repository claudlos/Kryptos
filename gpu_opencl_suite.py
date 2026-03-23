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
from kryptos.common import (
    analyze_layered_candidate,
    build_displacement_route_candidates,
    decrypt_bifid,
    extract_clue_hits,
    generate_polybius_square,
    mutate_polybius_square,
    preview_hash,
    preview_text,
    sort_ranked_candidates,
    transform_family,
)
from kryptos.constants import DEFAULT_PERIODS, K4
from kryptos.dashboard import write_json
from kryptos.paths import DEFAULT_DICTIONARY_PATH, resolve_repo_path


def load_dictionary(filepath: str) -> list[str]:
    path = resolve_repo_path(filepath)
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


FOCUS_CLUE_LETTERS = ("E", "A", "S", "T", "N", "O", "R", "H", "B", "L", "I", "C", "K")


def build_square_position_table(base_squares: list[str]) -> np.ndarray:
    positions = np.full((len(base_squares), 26), 255, dtype=np.uint8)
    for square_index, square in enumerate(base_squares):
        for offset, char in enumerate(square):
            positions[square_index, ord(char) - ord("A")] = offset
        positions[square_index, ord("J") - ord("A")] = positions[square_index, ord("I") - ord("A")]
    return positions.reshape(-1)


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
    const int sweep_idx,
    const int total_work_items
) {
    int gid = get_global_id(0);
    if (gid >= total_work_items) {
        return;
    }

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
    uchar bifid_stream[194];

    for (int block_start = 0; block_start < 97; block_start += period) {
        int end = block_start + period;
        if (end > 97) {
            end = 97;
        }

        int block_len = end - block_start;

        for (int i = 0; i < block_len; ++i) {
            uchar ch = k4[block_start + i];
            if (ch == 'J') {
                ch = 'I';
            }
            int ch_idx = ch - 'A';
            bifid_stream[2 * i] = r_map[ch_idx];
            bifid_stream[2 * i + 1] = c_map[ch_idx];
        }

        for (int i = 0; i < block_len; ++i) {
            int row_idx = bifid_stream[i];
            int col_idx = bifid_stream[block_len + i];
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

    int east_anywhere = contains_term(plaintext, 97, east_combined, 13);
    if (east_anywhere) {
        score += 20000;
        exact_match = 1;
    }
    int berlin_anywhere = contains_term(plaintext, 97, berlin_combined, 11);
    if (berlin_anywhere) {
        score += 18000;
        exact_match = 1;
    }

    // Most candidates never reach the anchor floor required for retention.
    // Bail out before the heavier language, periodic, displacement, and layer passes.
    if (!exact_match && anchor_hits < min_anchor_hits) {
        return;
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

__constant uchar FAST_EAST_COMBINED[13] = {'E','A','S','T','N','O','R','T','H','E','A','S','T'};
__constant uchar FAST_BERLIN_COMBINED[11] = {'B','E','R','L','I','N','C','L','O','C','K'};
__constant uchar FAST_EAST_COMPONENT[4] = {'E','A','S','T'};
__constant uchar FAST_NORTHEAST_COMPONENT[9] = {'N','O','R','T','H','E','A','S','T'};
__constant uchar FAST_BERLIN_COMPONENT[6] = {'B','E','R','L','I','N'};
__constant uchar FAST_CLOCK_COMPONENT[5] = {'C','L','O','C','K'};
__constant uchar FAST_WORLD_TERM[5] = {'W','O','R','L','D'};
__constant uchar FAST_MESSAGE_TERM[7] = {'M','E','S','S','A','G','E'};
__constant uchar FAST_EGYPT_TERM[5] = {'E','G','Y','P','T'};
__constant uchar FAST_WALL_TERM[4] = {'W','A','L','L'};
__constant uchar FAST_CIA_TERM[3] = {'C','I','A'};
__constant uchar FAST_LANGLEY_TERM[7] = {'L','A','N','G','L','E','Y'};
__constant uchar FAST_TOMB_TERM[4] = {'T','O','M','B'};
__constant uchar FAST_CARRY_TERM[5] = {'C','A','R','R','Y'};
__constant uchar FAST_SEND_TERM[4] = {'S','E','N','D'};
__constant uchar FAST_DELIVER_TERM[7] = {'D','E','L','I','V','E','R'};
__constant uchar FAST_THE_TERM[3] = {'T','H','E'};
__constant uchar FAST_ING_TERM[3] = {'I','N','G'};
__constant uchar FAST_ION_TERM[3] = {'I','O','N'};
__constant uchar FAST_ENT_TERM[3] = {'E','N','T'};
__constant uchar FAST_TION_TERM[4] = {'T','I','O','N'};
__constant uchar FAST_TIO_TERM[3] = {'T','I','O'};
__constant uchar FAST_HER_TERM[3] = {'H','E','R'};
__constant uchar FAST_ERE_TERM[3] = {'E','R','E'};
__constant uchar FAST_THA_TERM[3] = {'T','H','A'};
__constant uchar FAST_TER_TERM[3] = {'T','E','R'};
__constant uchar FAST_ATI_TERM[3] = {'A','T','I'};

inline int fast_match_term(__private const uchar* text, const int start, __constant const uchar* term, const int term_len) {
    for (int offset = 0; offset < term_len; ++offset) {
        if (text[start + offset] != term[offset]) {
            return 0;
        }
    }
    return 1;
}

inline void load_mutated_square_fast(
    __global const uchar* base_squares,
    __global const uchar* base_positions,
    const int base_square_idx,
    const int mut_id,
    __private uchar* local_square,
    __private uchar* local_positions
) {
    __global const uchar* global_square = &base_squares[base_square_idx * 25];
    __global const uchar* global_positions = &base_positions[base_square_idx * 26];
    for (int i = 0; i < 25; ++i) {
        local_square[i] = global_square[i];
    }
    for (int i = 0; i < 26; ++i) {
        local_positions[i] = global_positions[i];
    }

    if (mut_id <= 0) {
        return;
    }

    ulong seed = mut_id * 19937 + 123456789;
    for (int swap_idx = 0; swap_idx < 4; ++swap_idx) {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        int left = seed % 25;
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        int right = seed % 25;
        if (left == right) {
            continue;
        }

        uchar left_char = local_square[left];
        uchar right_char = local_square[right];
        local_square[left] = right_char;
        local_square[right] = left_char;
        local_positions[left_char - 'A'] = (uchar) right;
        local_positions[right_char - 'A'] = (uchar) left;
    }
}

inline void decode_plaintext_fast(
    __constant const uchar* k4,
    const int period,
    __private const uchar* local_square,
    __private const uchar* local_positions,
    __private uchar* plaintext
) {
    uchar block_stream[194];
    for (int block_start = 0; block_start < 97; block_start += period) {
        int end = block_start + period;
        if (end > 97) {
            end = 97;
        }
        int block_len = end - block_start;

        for (int offset = 0; offset < block_len; ++offset) {
            uchar ch = k4[block_start + offset];
            if (ch == 'J') {
                ch = 'I';
            }
            uchar position = local_positions[ch - 'A'];
            block_stream[2 * offset] = position / 5;
            block_stream[2 * offset + 1] = position % 5;
        }

        for (int offset = 0; offset < block_len; ++offset) {
            int row_idx = block_stream[offset];
            int col_idx = block_stream[block_len + offset];
            plaintext[block_start + offset] = local_square[row_idx * 5 + col_idx];
        }
    }
}

inline int score_displacement_hint_fast(__private const uchar* text, __private int* best_displacement_out) {
    int best_displacement_score = 0;
    int best_displacement_matches = 0;
    int best_displacement_exacts = 0;
    int best_displacement = 0;

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
                if (text[east_pos + i] == FAST_EAST_COMPONENT[i]) {
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
                if (text[northeast_pos + i] == FAST_NORTHEAST_COMPONENT[i]) {
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
                if (text[berlin_pos + i] == FAST_BERLIN_COMPONENT[i]) {
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
                if (text[clock_pos + i] == FAST_CLOCK_COMPONENT[i]) {
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
        int displacement_hint = min(best_displacement_score, 520);
        if (best_displacement_exacts >= 2) {
            displacement_hint = min(displacement_hint + 40, 560);
        }
        *best_displacement_out = best_displacement;
        return displacement_hint;
    }

    *best_displacement_out = 0;
    return 0;
}

inline void scan_plaintext_terms_fast(
    __private const uchar* text,
    __private int* score,
    __private int* context_hits,
    __private int* ngram_hint,
    __private int* exact_match
) {
    int east_anywhere = 0;
    int northeast_anywhere = 0;
    int berlin_anywhere = 0;
    int clock_anywhere = 0;
    int world_found = 0;
    int message_found = 0;
    int egypt_found = 0;
    int wall_found = 0;
    int cia_found = 0;
    int langley_found = 0;
    int tomb_found = 0;
    int carry_found = 0;
    int send_found = 0;
    int deliver_found = 0;
    int the_found = 0;
    int ing_found = 0;
    int ion_found = 0;
    int ent_found = 0;
    int tion_found = 0;
    int tio_found = 0;
    int her_found = 0;
    int ere_found = 0;
    int tha_found = 0;
    int ter_found = 0;
    int ati_found = 0;

    for (int start = 0; start < 97; ++start) {
        if (!east_anywhere && start <= 84 && fast_match_term(text, start, FAST_EAST_COMBINED, 13)) {
            east_anywhere = 1;
        }
        if (!northeast_anywhere && start <= 88 && fast_match_term(text, start, FAST_NORTHEAST_COMPONENT, 9)) {
            northeast_anywhere = 1;
        }
        if (!berlin_anywhere && start <= 86 && fast_match_term(text, start, FAST_BERLIN_COMBINED, 11)) {
            berlin_anywhere = 1;
        }
        if (!clock_anywhere && start <= 92 && fast_match_term(text, start, FAST_CLOCK_COMPONENT, 5)) {
            clock_anywhere = 1;
        }
        if (!world_found && start <= 92 && fast_match_term(text, start, FAST_WORLD_TERM, 5)) {
            world_found = 1;
        }
        if (!message_found && start <= 90 && fast_match_term(text, start, FAST_MESSAGE_TERM, 7)) {
            message_found = 1;
        }
        if (!egypt_found && start <= 92 && fast_match_term(text, start, FAST_EGYPT_TERM, 5)) {
            egypt_found = 1;
        }
        if (!wall_found && start <= 93 && fast_match_term(text, start, FAST_WALL_TERM, 4)) {
            wall_found = 1;
        }
        if (!cia_found && start <= 94 && fast_match_term(text, start, FAST_CIA_TERM, 3)) {
            cia_found = 1;
        }
        if (!langley_found && start <= 90 && fast_match_term(text, start, FAST_LANGLEY_TERM, 7)) {
            langley_found = 1;
        }
        if (!tomb_found && start <= 93 && fast_match_term(text, start, FAST_TOMB_TERM, 4)) {
            tomb_found = 1;
        }
        if (!carry_found && start <= 92 && fast_match_term(text, start, FAST_CARRY_TERM, 5)) {
            carry_found = 1;
        }
        if (!send_found && start <= 93 && fast_match_term(text, start, FAST_SEND_TERM, 4)) {
            send_found = 1;
        }
        if (!deliver_found && start <= 90 && fast_match_term(text, start, FAST_DELIVER_TERM, 7)) {
            deliver_found = 1;
        }
        if (!the_found && start <= 94 && fast_match_term(text, start, FAST_THE_TERM, 3)) {
            the_found = 1;
        }
        if (!ing_found && start <= 94 && fast_match_term(text, start, FAST_ING_TERM, 3)) {
            ing_found = 1;
        }
        if (!ion_found && start <= 94 && fast_match_term(text, start, FAST_ION_TERM, 3)) {
            ion_found = 1;
        }
        if (!ent_found && start <= 94 && fast_match_term(text, start, FAST_ENT_TERM, 3)) {
            ent_found = 1;
        }
        if (!tion_found && start <= 93 && fast_match_term(text, start, FAST_TION_TERM, 4)) {
            tion_found = 1;
        }
        if (!tio_found && start <= 94 && fast_match_term(text, start, FAST_TIO_TERM, 3)) {
            tio_found = 1;
        }
        if (!her_found && start <= 94 && fast_match_term(text, start, FAST_HER_TERM, 3)) {
            her_found = 1;
        }
        if (!ere_found && start <= 94 && fast_match_term(text, start, FAST_ERE_TERM, 3)) {
            ere_found = 1;
        }
        if (!tha_found && start <= 94 && fast_match_term(text, start, FAST_THA_TERM, 3)) {
            tha_found = 1;
        }
        if (!ter_found && start <= 94 && fast_match_term(text, start, FAST_TER_TERM, 3)) {
            ter_found = 1;
        }
        if (!ati_found && start <= 94 && fast_match_term(text, start, FAST_ATI_TERM, 3)) {
            ati_found = 1;
        }
    }

    if (east_anywhere) {
        *score += 20000;
        *exact_match = 1;
    }
    if (berlin_anywhere) {
        *score += 18000;
        *exact_match = 1;
    }
    if (east_anywhere || fast_match_term(text, 21, FAST_EAST_COMPONENT, 4)) {
        *score += 140;
    }
    if (northeast_anywhere) {
        *score += 220;
    }
    if (berlin_anywhere || fast_match_term(text, 63, FAST_BERLIN_COMPONENT, 6)) {
        *score += 180;
    }
    if (clock_anywhere) {
        *score += 180;
    }
    if (world_found) {
        *score += 180;
        *context_hits += 1;
    }
    if (message_found) {
        *score += 180;
        *context_hits += 1;
    }
    if (egypt_found) {
        *score += 150;
        *context_hits += 1;
    }
    if (wall_found) {
        *score += 120;
        *context_hits += 1;
    }
    if (cia_found) {
        *score += 90;
        *context_hits += 1;
    }
    if (langley_found) {
        *score += 150;
        *context_hits += 1;
    }
    if (tomb_found) {
        *score += 120;
        *context_hits += 1;
    }
    if (carry_found) {
        *score += 100;
        *context_hits += 1;
    }
    if (send_found) {
        *score += 100;
        *context_hits += 1;
    }
    if (deliver_found) {
        *score += 150;
        *context_hits += 1;
    }
    if (the_found) {
        *ngram_hint += 80;
    }
    if (ing_found) {
        *ngram_hint += 60;
    }
    if (ion_found) {
        *ngram_hint += 60;
    }
    if (ent_found) {
        *ngram_hint += 60;
    }
    if (tion_found) {
        *ngram_hint += 90;
    }
    if (tio_found) {
        *ngram_hint += 55;
    }
    if (her_found) {
        *ngram_hint += 55;
    }
    if (ere_found) {
        *ngram_hint += 55;
    }
    if (tha_found) {
        *ngram_hint += 55;
    }
    if (ter_found) {
        *ngram_hint += 55;
    }
    if (ati_found) {
        *ngram_hint += 55;
    }
}

inline int score_language_features_fast(__private const uchar* text, __private int* score) {
    int vowel_count = 0;
    int harsh_count = 0;
    for (int i = 0; i < 97; ++i) {
        uchar ch = text[i];
        if (ch == 'A' || ch == 'E' || ch == 'I' || ch == 'O' || ch == 'U' || ch == 'Y') {
            vowel_count++;
        }
        if (ch == 'Q' || ch == 'Z' || ch == 'X' || ch == 'J') {
            harsh_count++;
        }
    }

    int language_hint = 0;
    int vowel_pct = vowel_count * 100;
    if (vowel_pct >= 24 * 97 && vowel_pct <= 48 * 97) {
        *score += 220;
        language_hint += 220;
    } else if (vowel_pct >= 18 * 97 && vowel_pct <= 55 * 97) {
        *score += 90;
        language_hint += 90;
    }
    if (harsh_count * 100 <= 14 * 97) {
        *score += 120;
        language_hint += 120;
    }
    return language_hint;
}

inline int score_periodic_features_fast(__private const uchar* text) {
    int periodic_hint = 0;
    int periodic_widths[4] = {5, 7, 9, 12};
    for (int width_index = 0; width_index < 4; ++width_index) {
        int width = periodic_widths[width_index];
        int single_matches = count_periodic_matches(text, 97, width);
        if (single_matches >= 4) {
            periodic_hint += min(single_matches * 14, 140);
        }

        int digram_matches = count_periodic_digrams(text, 97, width);
        if (digram_matches > 0) {
            periodic_hint += min(digram_matches * 45, 180);
        }
    }
    return periodic_hint;
}

inline int score_layer_hint_fast(__private const uchar* text, const int max_post_key_length) {
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
            int shift = ((int) text[21 + i] - (int) FAST_EAST_COMBINED[i] + 26) % 26;
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
            int shift = ((int) text[63 + i] - (int) FAST_BERLIN_COMBINED[i] + 26) % 26;
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
    return best_layer_hint;
}

__kernel void score_bifid_anchors_fast(
    __constant const uchar* k4,
    __global const uchar* base_squares,
    __global const uchar* base_positions,
    __constant const int* periods,
    const int num_periods,
    const int num_base_squares,
    const int copies_per_sweep,
    const int min_anchor_hits,
    __global int* candidate_gids,
    __global int* candidate_sweeps,
    __global int* candidate_scores,
    __global int* candidate_flags,
    __global int* candidate_anchor_hits,
    __global int* candidate_displacement_hints,
    __global int* candidate_best_displacements,
    volatile __global int* candidate_count,
    volatile __global int* exact_match_count,
    const int candidate_limit,
    const int sweep_idx,
    const int total_work_items
) {
    int gid = get_global_id(0);
    if (gid >= total_work_items) {
        return;
    }

    int period_index = gid % num_periods;
    int square_index = gid / num_periods;
    int base_square_idx = square_index % num_base_squares;
    int copy_idx = square_index / num_base_squares;
    int mut_id = sweep_idx * copies_per_sweep + copy_idx;
    int period = periods[period_index];

    uchar local_square[25];
    uchar local_positions[26];
    uchar plaintext[97];
    load_mutated_square_fast(base_squares, base_positions, base_square_idx, mut_id, local_square, local_positions);
    decode_plaintext_fast(k4, period, local_square, local_positions, plaintext);

    int score = 0;
    int exact_match = 0;
    int east_matches = 0;
    int berlin_matches = 0;
    for (int i = 0; i < 13; ++i) {
        if (plaintext[21 + i] == FAST_EAST_COMBINED[i]) {
            east_matches++;
            score += 180;
        }
        if (i < 12 && plaintext[21 + i] == FAST_EAST_COMBINED[i] && plaintext[21 + i + 1] == FAST_EAST_COMBINED[i + 1]) {
            score += 80;
        }
    }
    for (int i = 0; i < 11; ++i) {
        if (plaintext[63 + i] == FAST_BERLIN_COMBINED[i]) {
            berlin_matches++;
            score += 180;
        }
        if (i < 10 && plaintext[63 + i] == FAST_BERLIN_COMBINED[i] && plaintext[63 + i + 1] == FAST_BERLIN_COMBINED[i + 1]) {
            score += 80;
        }
    }

    int anchor_hits = east_matches + berlin_matches;
    int east_exact = 1;
    for (int i = 0; i < 4; ++i) {
        if (plaintext[21 + i] != FAST_EAST_COMPONENT[i]) {
            east_exact = 0;
        }
    }
    if (east_exact) {
        score += 900;
    }

    int northeast_exact = 1;
    for (int i = 0; i < 9; ++i) {
        if (plaintext[25 + i] != FAST_NORTHEAST_COMPONENT[i]) {
            northeast_exact = 0;
        }
    }
    if (northeast_exact) {
        score += 1400;
    }

    int berlin_exact = 1;
    for (int i = 0; i < 6; ++i) {
        if (plaintext[63 + i] != FAST_BERLIN_COMPONENT[i]) {
            berlin_exact = 0;
        }
    }
    if (berlin_exact) {
        score += 1200;
    }

    int clock_exact = 1;
    for (int i = 0; i < 5; ++i) {
        if (plaintext[69 + i] != FAST_CLOCK_COMPONENT[i]) {
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

    if (!exact_match && anchor_hits < min_anchor_hits) {
        return;
    }

    int best_displacement = 0;
    int displacement_hint = score_displacement_hint_fast(plaintext, &best_displacement);
    if (exact_match) {
        atomic_add(exact_match_count, 1);
    }

    int idx = atomic_add(candidate_count, 1);
    if (idx < candidate_limit) {
        candidate_gids[idx] = gid;
        candidate_sweeps[idx] = sweep_idx;
        candidate_scores[idx] = score;
        candidate_flags[idx] = exact_match;
        candidate_anchor_hits[idx] = anchor_hits;
        candidate_displacement_hints[idx] = displacement_hint;
        candidate_best_displacements[idx] = best_displacement;
    }
}

__kernel void hydrate_bifid_candidates_fast(
    __constant const uchar* k4,
    __global const uchar* base_squares,
    __global const uchar* base_positions,
    __constant const int* periods,
    const int num_periods,
    const int num_base_squares,
    const int copies_per_sweep,
    const int max_post_key_length,
    const int min_anchor_hits,
    const int score_threshold,
    __global const int* candidate_gids,
    __global const int* candidate_sweeps,
    __global int* candidate_scores,
    __global int* candidate_flags,
    __global uint* candidate_hashes,
    __global const int* candidate_anchor_hits,
    __global int* candidate_context_hits,
    __global int* candidate_language_hints,
    __global int* candidate_ngram_hints,
    __global int* candidate_periodic_hints,
    __global int* candidate_displacement_hints,
    __global int* candidate_best_displacements,
    __global int* candidate_layer_hints,
    __global int* candidate_eligibility_flags,
    const int stored_candidate_count
) {
    int slot = get_global_id(0);
    if (slot >= stored_candidate_count) {
        return;
    }

    int raw_gid = candidate_gids[slot];
    if (raw_gid < 0) {
        candidate_eligibility_flags[slot] = 0;
        return;
    }

    int sweep_idx = candidate_sweeps[slot];
    int period_index = raw_gid % num_periods;
    int square_index = raw_gid / num_periods;
    int base_square_idx = square_index % num_base_squares;
    int copy_idx = square_index / num_base_squares;
    int mut_id = sweep_idx * copies_per_sweep + copy_idx;
    int period = periods[period_index];

    uchar local_square[25];
    uchar local_positions[26];
    uchar plaintext[97];
    load_mutated_square_fast(base_squares, base_positions, base_square_idx, mut_id, local_square, local_positions);
    decode_plaintext_fast(k4, period, local_square, local_positions, plaintext);

    int score = candidate_scores[slot];
    int exact_match = candidate_flags[slot];
    int context_hits = 0;
    int ngram_hint = 0;
    scan_plaintext_terms_fast(plaintext, &score, &context_hits, &ngram_hint, &exact_match);
    int language_hint = score_language_features_fast(plaintext, &score);
    int periodic_hint = score_periodic_features_fast(plaintext);
    int layer_hint = score_layer_hint_fast(plaintext, max_post_key_length);
    score += layer_hint;

    candidate_scores[slot] = score;
    candidate_flags[slot] = exact_match;
    candidate_hashes[slot] = hash_plaintext(plaintext, 97);
    candidate_context_hits[slot] = context_hits;
    candidate_language_hints[slot] = language_hint;
    candidate_ngram_hints[slot] = ngram_hint;
    candidate_periodic_hints[slot] = periodic_hint;
    candidate_layer_hints[slot] = layer_hint;
    candidate_eligibility_flags[slot] = exact_match || (candidate_anchor_hits[slot] >= min_anchor_hits && score >= score_threshold);
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
    parser.add_argument("--local-size", type=int, help="Explicit local workgroup size for OpenCL kernel launches.")
    parser.add_argument("--focus-budget", type=int, help="Adaptive follow-up evaluations to allocate across the strongest hydrated candidates.")
    parser.add_argument("--focus-seed-limit", type=int, help="Maximum number of hydrated candidates to use as adaptive follow-up seeds.")
    parser.add_argument("--focus-neighbor-span", type=int, help="Maximum grid distance for survivor-guided local swap follow-up.")
    parser.add_argument("--json", action="store_true", help="Emit the final summary as JSON.")
    parser.add_argument("--output", help="Write the final summary to a JSON file.")
    return parser.parse_args()


def resolve_profile_config(args: argparse.Namespace) -> dict[str, Any]:
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
        "local_size": args.local_size if args.local_size is not None else profile.get("local_size"),
        "focus_budget": args.focus_budget if args.focus_budget is not None else int(profile.get("focus_budget", 0)),
        "focus_seed_limit": args.focus_seed_limit if args.focus_seed_limit is not None else int(profile.get("focus_seed_limit", 0)),
        "focus_neighbor_span": args.focus_neighbor_span if args.focus_neighbor_span is not None else int(profile.get("focus_neighbor_span", 1)),
    }
    config["max_post_key_length"] = min(max(config["max_post_key_length"], 1), 12)
    config["top_candidate_limit"] = min(max(config["top_candidate_limit"], 1), config["match_limit"])
    config["hydrate_limit"] = min(max(config["hydrate_limit"], config["top_candidate_limit"]), config["match_limit"])
    config["min_anchor_hits"] = min(max(config["min_anchor_hits"], 1), 24)
    config["focus_budget"] = max(int(config["focus_budget"]), 0)
    config["focus_seed_limit"] = max(int(config["focus_seed_limit"]), 0)
    config["focus_neighbor_span"] = max(int(config["focus_neighbor_span"]), 1)
    if config["local_size"] is not None:
        config["local_size"] = max(int(config["local_size"]), 1)
    return config


def round_up_to_multiple(value: int, multiple: int) -> int:
    if multiple <= 0:
        raise ValueError("multiple must be positive")
    return ((value + multiple - 1) // multiple) * multiple


def resolve_work_sizes(
    total_work_items: int,
    local_size: int | None,
    *,
    device: Any,
    kernel: Any,
) -> tuple[tuple[int], tuple[int] | None]:
    if local_size is None:
        return (total_work_items,), None
    kernel_max = int(kernel.get_work_group_info(cl.kernel_work_group_info.WORK_GROUP_SIZE, device))
    device_max = int(device.max_work_group_size)
    allowed_max = min(kernel_max, device_max)
    if local_size > allowed_max:
        raise ValueError(
            f"Requested local size {local_size} exceeds the supported maximum {allowed_max} for {device.name}."
        )
    global_work_items = round_up_to_multiple(total_work_items, local_size)
    return (global_work_items,), (local_size,)


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
    # The kernel overwrites every payload slot up to candidate_count on each pass,
    # and host-side hydration only reads that populated prefix back.
    # Resetting the counters is enough to make the next pass authoritative.
    candidate_count_np.fill(0)
    exact_match_count_np.fill(0)
    cl.enqueue_copy(queue, candidate_count_buffer, candidate_count_np)
    cl.enqueue_copy(queue, exact_match_count_buffer, exact_match_count_np)


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


def merge_top_raw_candidates(
    existing: list[dict[str, int | bool]],
    incoming: list[dict[str, int | bool]],
    *,
    max_entries: int,
) -> list[dict[str, int | bool]]:
    if max_entries <= 0:
        return []
    merged_by_signature: dict[tuple[int, int], dict[str, int | bool]] = {}
    for entry in [*existing, *incoming]:
        signature = (int(entry["raw_gid"]), int(entry["sweep_index"]))
        current = merged_by_signature.get(signature)
        if current is None:
            merged_by_signature[signature] = entry
            continue
        merged_by_signature[signature] = sort_raw_candidate_entries([current, entry])[0]
    return sort_raw_candidate_entries(list(merged_by_signature.values()))[:max_entries]


def dedupe_candidate_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: list[dict[str, object]] = []
    seen_signatures: set[tuple[tuple[str, ...], str]] = set()
    for record in sort_candidate_records(records):
        signature = (
            transform_family(list(record["transform_chain"])),
            preview_hash(str(record["best_preview"])),
        )
        if signature in seen_signatures:
            continue
        deduped.append(record)
        seen_signatures.add(signature)
    return sort_candidate_records(deduped)


def raw_candidate_from_record(record: dict[str, object]) -> dict[str, int | bool]:
    return build_raw_candidate_entry(
        raw_gid=int(record["raw_gid"]),
        sweep_index=int(record["sweep_index"]),
        raw_score=int(record["raw_score"]),
        exact_match=bool(record["exact_match"]),
        plaintext_hash=int(record["plaintext_hash"]),
        anchor_hits=int(record["raw_anchor_hits"]),
        context_hits=int(record["raw_context_hits"]),
        language_hint=int(record["raw_language_hint"]),
        ngram_hint=int(record.get("raw_ngram_hint", 0)),
        periodic_hint=int(record.get("raw_periodic_hint", 0)),
        displacement_hint=int(record.get("raw_displacement_hint", 0)),
        best_displacement=int(record.get("raw_best_displacement", 0)),
        layer_hint=int(record["raw_layer_hint"]),
    )


def build_candidate_record_from_plaintext(
    raw_candidate: dict[str, int | bool],
    *,
    keyword: str,
    base_square_index: int,
    period: int,
    mutation_id: int,
    direct_plaintext: str,
    max_post_key_length: int,
    displacement_window: int = 24,
    route_followup_limit: int = 2,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    layered = analyze_layered_candidate(direct_plaintext, max_key_length=max_post_key_length)
    best_candidate = {
        "rank": 0,
        "total_score": int(layered["score"]),
        "breakdown": dict(layered["breakdown"]),
        "transform_chain": list(layered["transform_chain"]),
        "key_material": dict(layered["key_material"]),
        "corpus_id": None,
        "preview": str(layered["preview"]),
        "matched_clues": list(layered["matched_clues"]),
        "plaintext": str(layered["plaintext"]),
    }
    preferred_deltas = ()
    if int(raw_candidate.get("best_displacement", 0)):
        preferred_deltas = (int(raw_candidate["best_displacement"]),)
    displacement_candidates = build_displacement_route_candidates(
        direct_plaintext,
        transform_chain=["direct"],
        scorer_profile="anchor-first",
        displacement_window=displacement_window,
        route_followup_limit=route_followup_limit,
        preferred_deltas=preferred_deltas,
    )
    if displacement_candidates:
        best_candidate = sort_ranked_candidates([best_candidate, *displacement_candidates])[0]
    best_mode = str(layered["mode"])
    if list(best_candidate["transform_chain"]) != list(layered["transform_chain"]):
        best_mode = "displacement_route"
    record = {
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
        "base_square_index": base_square_index,
        "period": period,
        "mutation_id": mutation_id,
        "sweep_index": int(raw_candidate["sweep_index"]),
        "direct_preview": preview_text(direct_plaintext),
        "direct_clue_hits": extract_clue_hits(direct_plaintext),
        "best_mode": best_mode,
        "best_score": int(best_candidate["total_score"]),
        "derived_key": layered["derived_key"] if best_mode != "displacement_route" else None,
        "key_length": layered["key_length"] if best_mode != "displacement_route" else None,
        "matched_clues": list(best_candidate["matched_clues"]),
        "best_preview": str(best_candidate["preview"]),
        "transform_chain": list(best_candidate["transform_chain"]),
        "key_material": dict(best_candidate["key_material"]),
        "geo_route_total": int(best_candidate.get("geo_route_total", 0)),
    }
    if metadata:
        record.update(metadata)
    return record


def build_candidate_record(
    raw_candidate: dict[str, int | bool],
    *,
    words: list[str],
    base_squares: list[str],
    num_periods: int,
    num_base_squares: int,
    copies_per_sweep: int,
    max_post_key_length: int,
    displacement_window: int = 24,
    route_followup_limit: int = 2,
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
    return build_candidate_record_from_plaintext(
        raw_candidate,
        keyword=keyword,
        base_square_index=identity["base_square_index"],
        period=identity["period"],
        mutation_id=identity["mutation_id"],
        direct_plaintext=direct_plaintext,
        max_post_key_length=max_post_key_length,
        displacement_window=displacement_window,
        route_followup_limit=route_followup_limit,
    )


def focus_seed_weight(record: dict[str, object]) -> int:
    return max(
        1,
        int(record["best_score"])
        + int(record.get("geo_route_total", 0))
        + int(record.get("raw_displacement_hint", 0))
        + int(record.get("raw_periodic_hint", 0))
        + (len(record.get("matched_clues", [])) * 80),
    )


def allocate_focus_budgets(
    records: list[dict[str, object]],
    *,
    total_budget: int,
    seed_limit: int,
) -> list[dict[str, object]]:
    if total_budget <= 0 or seed_limit <= 0:
        return []
    seeds = sort_candidate_records(records)[:seed_limit]
    if not seeds:
        return []
    if total_budget <= len(seeds):
        return [{"seed": seed, "budget": 1} for seed in seeds[:total_budget]]

    plans = [{"seed": seed, "budget": 1, "weight": focus_seed_weight(seed)} for seed in seeds]
    remaining = total_budget - len(plans)
    while remaining > 0:
        for plan in sorted(plans, key=lambda item: (int(item["weight"]), int(item["budget"])), reverse=True):
            plan["budget"] = int(plan["budget"]) + 1
            remaining -= 1
            if remaining <= 0:
                break
    return [{"seed": plan["seed"], "budget": int(plan["budget"])} for plan in plans]


def swap_square_positions(square: str, left: int, right: int) -> str:
    chars = list(square)
    chars[left], chars[right] = chars[right], chars[left]
    return "".join(chars)


def iter_local_swap_variants(square: str, *, limit: int, span: int) -> list[tuple[str, list[str]]]:
    if limit <= 0:
        return []
    positions = {char: index for index, char in enumerate(square)}
    variants: list[tuple[str, list[str]]] = []
    seen: set[str] = {square}

    def add_variant(left: int, right: int, label: str) -> None:
        if left == right or not (0 <= left < 25 and 0 <= right < 25):
            return
        candidate = swap_square_positions(square, left, right)
        if candidate in seen:
            return
        seen.add(candidate)
        variants.append((candidate, [label]))

    for clue_char in FOCUS_CLUE_LETTERS:
        left = positions.get(clue_char)
        if left is None:
            continue
        row, col = divmod(left, 5)
        for distance in range(1, max(span, 1) + 1):
            if col - distance >= 0:
                add_variant(left, row * 5 + (col - distance), f"{clue_char}<->left{distance}")
            if col + distance < 5:
                add_variant(left, row * 5 + (col + distance), f"{clue_char}<->right{distance}")
            if row - distance >= 0:
                add_variant(left, (row - distance) * 5 + col, f"{clue_char}<->up{distance}")
            if row + distance < 5:
                add_variant(left, (row + distance) * 5 + col, f"{clue_char}<->down{distance}")
            if len(variants) >= limit:
                return variants[:limit]

    clue_positions = [(char, positions[char]) for char in FOCUS_CLUE_LETTERS if char in positions]
    for index, (left_char, left_pos) in enumerate(clue_positions):
        for right_char, right_pos in clue_positions[index + 1:]:
            add_variant(left_pos, right_pos, f"{left_char}<->{right_char}")
            if len(variants) >= limit:
                return variants[:limit]
    return variants[:limit]


def run_focus_followup(
    records: list[dict[str, object]],
    *,
    base_squares: list[str],
    max_post_key_length: int,
    displacement_window: int,
    route_followup_limit: int,
    focus_budget: int,
    focus_seed_limit: int,
    focus_neighbor_span: int,
) -> list[dict[str, object]]:
    focused_records: list[dict[str, object]] = []
    for plan in allocate_focus_budgets(records, total_budget=focus_budget, seed_limit=focus_seed_limit):
        seed = plan["seed"]
        base_square = mutate_polybius_square(
            base_squares[int(seed["base_square_index"])],
            int(seed["mutation_id"]),
        )
        raw_candidate = raw_candidate_from_record(seed)
        for variant_square, swap_labels in iter_local_swap_variants(
            base_square,
            limit=int(plan["budget"]),
            span=focus_neighbor_span,
        ):
            direct_plaintext = decrypt_bifid(int(seed["period"]), K4, variant_square)
            focused_records.append(
                build_candidate_record_from_plaintext(
                    raw_candidate,
                    keyword=str(seed["keyword"]),
                    base_square_index=int(seed["base_square_index"]),
                    period=int(seed["period"]),
                    mutation_id=int(seed["mutation_id"]),
                    direct_plaintext=direct_plaintext,
                    max_post_key_length=max_post_key_length,
                    displacement_window=displacement_window,
                    route_followup_limit=route_followup_limit,
                    metadata={
                        "focus_local_search": True,
                        "focus_swap_labels": list(swap_labels),
                        "focus_source_preview": str(seed["best_preview"]),
                    },
                )
            )
    return dedupe_candidate_records(focused_records)


def sort_candidate_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        records,
        key=lambda record: (
            int(bool(record["exact_match"])),
            len(record["matched_clues"]),
            int(record["best_score"]),
            int(record.get("geo_route_total", 0)),
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
    config = resolve_profile_config(args)
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
    square_positions_np = build_square_position_table(base_squares)
    square_positions_buffer = cl.Buffer(ctx, mem_flags.READ_ONLY | mem_flags.COPY_HOST_PTR, hostbuf=square_positions_np)

    periods = np.array(DEFAULT_PERIODS, dtype=np.int32)
    periods_buffer = cl.Buffer(ctx, mem_flags.READ_ONLY | mem_flags.COPY_HOST_PTR, hostbuf=periods)
    num_periods = len(periods)
    num_base_squares = len(base_squares)
    total_work_items = num_base_squares * config["copies_per_sweep"] * num_periods
    coarse_buffer_limit = max(config["match_limit"] * 8, config["hydrate_limit"] * 32, 65536)
    coarse_retained_limit = max(config["match_limit"] * 4, config["hydrate_limit"] * 16, 4096)

    candidate_gids_np = np.full(coarse_buffer_limit, -1, dtype=np.int32)
    candidate_gids_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_gids_np)
    candidate_sweeps_np = np.full(coarse_buffer_limit, -1, dtype=np.int32)
    candidate_sweeps_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_sweeps_np)
    candidate_scores_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_scores_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_scores_np)
    candidate_flags_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_flags_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_flags_np)
    candidate_hashes_np = np.zeros(coarse_buffer_limit, dtype=np.uint32)
    candidate_hashes_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_hashes_np)
    candidate_anchor_hits_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_anchor_hits_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_anchor_hits_np)
    candidate_context_hits_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_context_hits_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_context_hits_np)
    candidate_language_hints_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_language_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_language_hints_np)
    candidate_ngram_hints_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_ngram_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_ngram_hints_np)
    candidate_periodic_hints_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_periodic_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_periodic_hints_np)
    candidate_displacement_hints_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_displacement_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_displacement_hints_np)
    candidate_best_displacements_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_best_displacements_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_best_displacements_np)
    candidate_layer_hints_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_layer_hints_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_layer_hints_np)
    candidate_eligibility_np = np.zeros(coarse_buffer_limit, dtype=np.int32)
    candidate_eligibility_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_eligibility_np)
    candidate_count_np = np.zeros(1, dtype=np.int32)
    candidate_count_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=candidate_count_np)
    exact_match_count_np = np.zeros(1, dtype=np.int32)
    exact_match_count_buffer = cl.Buffer(ctx, mem_flags.READ_WRITE | mem_flags.COPY_HOST_PTR, hostbuf=exact_match_count_np)

    anchor_kernel = cl.Kernel(program, "score_bifid_anchors_fast")
    hydrate_kernel = cl.Kernel(program, "hydrate_bifid_candidates_fast")
    global_work_shape, local_work_shape = resolve_work_sizes(
        total_work_items,
        int(config["local_size"]) if config["local_size"] is not None else None,
        device=device,
        kernel=anchor_kernel,
    )
    pass_summaries: list[dict[str, object]] = []
    overall_candidates: list[dict[str, object]] = []
    total_decryptions = 0
    total_qualified_candidates = 0
    total_hydrated_candidates = 0
    total_focused_candidates = 0
    pass_number = 1
    benchmark_record = build_benchmark_record(
        "gpu-opencl",
        args.profile,
        {
            **config,
            "dictionary": str(resolve_repo_path(args.dictionary)),
            "periods": list(DEFAULT_PERIODS),
            "continuous": args.continuous,
        },
        command=sys.argv,
    )

    try:
        while args.continuous or pass_number <= config["passes"]:
            pass_started = time.time()
            pass_decryptions = 0
            sweep_offset = (pass_number - 1) * config["sweeps_per_pass"]
            coarse_candidate_count = 0
            coarse_stored_candidate_count = 0
            coarse_overflow_count = 0
            pass_exact_match_count = 0
            pass_raw_candidates: list[dict[str, int | bool]] = []

            for sweep in range(config["sweeps_per_pass"]):
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
                anchor_kernel(
                    queue,
                    global_work_shape,
                    local_work_shape,
                    k4_buffer,
                    squares_buffer,
                    square_positions_buffer,
                    periods_buffer,
                    np.int32(num_periods),
                    np.int32(num_base_squares),
                    np.int32(config["copies_per_sweep"]),
                    np.int32(config["min_anchor_hits"]),
                    candidate_gids_buffer,
                    candidate_sweeps_buffer,
                    candidate_scores_buffer,
                    candidate_flags_buffer,
                    candidate_anchor_hits_buffer,
                    candidate_displacement_hints_buffer,
                    candidate_best_displacements_buffer,
                    candidate_count_buffer,
                    exact_match_count_buffer,
                    np.int32(coarse_buffer_limit),
                    np.int32(sweep_offset + sweep),
                    np.int32(total_work_items),
                )
                pass_decryptions += total_work_items
                cl.enqueue_copy(queue, candidate_count_np, candidate_count_buffer)
                cl.enqueue_copy(queue, exact_match_count_np, exact_match_count_buffer)
                queue.finish()

                sweep_candidate_count = int(candidate_count_np[0])
                coarse_candidate_count += sweep_candidate_count
                pass_exact_match_count += int(exact_match_count_np[0])
                stored_sweep_candidate_count = min(sweep_candidate_count, coarse_buffer_limit)
                coarse_stored_candidate_count += stored_sweep_candidate_count
                coarse_overflow_count += max(sweep_candidate_count - stored_sweep_candidate_count, 0)

                if stored_sweep_candidate_count <= 0:
                    continue

                cl.enqueue_copy(queue, candidate_gids_np[:stored_sweep_candidate_count], candidate_gids_buffer)
                cl.enqueue_copy(queue, candidate_sweeps_np[:stored_sweep_candidate_count], candidate_sweeps_buffer)
                cl.enqueue_copy(queue, candidate_scores_np[:stored_sweep_candidate_count], candidate_scores_buffer)
                cl.enqueue_copy(queue, candidate_flags_np[:stored_sweep_candidate_count], candidate_flags_buffer)
                cl.enqueue_copy(queue, candidate_anchor_hits_np[:stored_sweep_candidate_count], candidate_anchor_hits_buffer)
                cl.enqueue_copy(queue, candidate_displacement_hints_np[:stored_sweep_candidate_count], candidate_displacement_hints_buffer)
                cl.enqueue_copy(queue, candidate_best_displacements_np[:stored_sweep_candidate_count], candidate_best_displacements_buffer)
                queue.finish()

                sweep_raw_candidates = [
                    build_raw_candidate_entry(
                        raw_gid=int(candidate_gids_np[index]),
                        sweep_index=int(candidate_sweeps_np[index]),
                        raw_score=int(candidate_scores_np[index]),
                        exact_match=bool(candidate_flags_np[index]),
                        plaintext_hash=0,
                        anchor_hits=int(candidate_anchor_hits_np[index]),
                        context_hits=0,
                        language_hint=0,
                        ngram_hint=0,
                        periodic_hint=0,
                        displacement_hint=int(candidate_displacement_hints_np[index]),
                        best_displacement=int(candidate_best_displacements_np[index]),
                        layer_hint=0,
                    )
                    for index in range(stored_sweep_candidate_count)
                ]
                pass_raw_candidates = merge_top_raw_candidates(
                    pass_raw_candidates,
                    sweep_raw_candidates,
                    max_entries=coarse_retained_limit,
                )

            stored_coarse_candidate_count = len(pass_raw_candidates)
            qualified_candidate_count = 0
            stored_candidate_count = 0
            hydrated_candidate_count = 0
            focused_candidate_count = 0
            pass_candidates: list[dict[str, object]] = []

            if stored_coarse_candidate_count > 0:
                candidate_gids_np[:stored_coarse_candidate_count] = np.array(
                    [int(entry["raw_gid"]) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_sweeps_np[:stored_coarse_candidate_count] = np.array(
                    [int(entry["sweep_index"]) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_scores_np[:stored_coarse_candidate_count] = np.array(
                    [int(entry["raw_score"]) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_flags_np[:stored_coarse_candidate_count] = np.array(
                    [int(bool(entry["exact_match"])) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_anchor_hits_np[:stored_coarse_candidate_count] = np.array(
                    [int(entry["anchor_hits"]) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_displacement_hints_np[:stored_coarse_candidate_count] = np.array(
                    [int(entry["displacement_hint"]) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_best_displacements_np[:stored_coarse_candidate_count] = np.array(
                    [int(entry["best_displacement"]) for entry in pass_raw_candidates],
                    dtype=np.int32,
                )
                candidate_hashes_np[:stored_coarse_candidate_count].fill(0)
                candidate_context_hits_np[:stored_coarse_candidate_count].fill(0)
                candidate_language_hints_np[:stored_coarse_candidate_count].fill(0)
                candidate_ngram_hints_np[:stored_coarse_candidate_count].fill(0)
                candidate_periodic_hints_np[:stored_coarse_candidate_count].fill(0)
                candidate_layer_hints_np[:stored_coarse_candidate_count].fill(0)
                candidate_eligibility_np[:stored_coarse_candidate_count].fill(0)

                cl.enqueue_copy(queue, candidate_gids_buffer, candidate_gids_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_sweeps_buffer, candidate_sweeps_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_scores_buffer, candidate_scores_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_flags_buffer, candidate_flags_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_anchor_hits_buffer, candidate_anchor_hits_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_displacement_hints_buffer, candidate_displacement_hints_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_best_displacements_buffer, candidate_best_displacements_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_hashes_buffer, candidate_hashes_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_context_hits_buffer, candidate_context_hits_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_language_hints_buffer, candidate_language_hints_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_ngram_hints_buffer, candidate_ngram_hints_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_periodic_hints_buffer, candidate_periodic_hints_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_layer_hints_buffer, candidate_layer_hints_np[:stored_coarse_candidate_count])
                cl.enqueue_copy(queue, candidate_eligibility_buffer, candidate_eligibility_np[:stored_coarse_candidate_count])
                queue.finish()

                hydrate_global_shape, hydrate_local_shape = resolve_work_sizes(
                    stored_coarse_candidate_count,
                    int(config["local_size"]) if config["local_size"] is not None else None,
                    device=device,
                    kernel=hydrate_kernel,
                )
                hydrate_kernel(
                    queue,
                    hydrate_global_shape,
                    hydrate_local_shape,
                    k4_buffer,
                    squares_buffer,
                    square_positions_buffer,
                    periods_buffer,
                    np.int32(num_periods),
                    np.int32(num_base_squares),
                    np.int32(config["copies_per_sweep"]),
                    np.int32(config["max_post_key_length"]),
                    np.int32(config["min_anchor_hits"]),
                    np.int32(config["score_threshold"]),
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
                    candidate_eligibility_buffer,
                    np.int32(stored_coarse_candidate_count),
                )
                cl.enqueue_copy(queue, candidate_gids_np[:stored_coarse_candidate_count], candidate_gids_buffer)
                cl.enqueue_copy(queue, candidate_sweeps_np[:stored_coarse_candidate_count], candidate_sweeps_buffer)
                cl.enqueue_copy(queue, candidate_scores_np[:stored_coarse_candidate_count], candidate_scores_buffer)
                cl.enqueue_copy(queue, candidate_flags_np[:stored_coarse_candidate_count], candidate_flags_buffer)
                cl.enqueue_copy(queue, candidate_hashes_np[:stored_coarse_candidate_count], candidate_hashes_buffer)
                cl.enqueue_copy(queue, candidate_anchor_hits_np[:stored_coarse_candidate_count], candidate_anchor_hits_buffer)
                cl.enqueue_copy(queue, candidate_context_hits_np[:stored_coarse_candidate_count], candidate_context_hits_buffer)
                cl.enqueue_copy(queue, candidate_language_hints_np[:stored_coarse_candidate_count], candidate_language_hints_buffer)
                cl.enqueue_copy(queue, candidate_ngram_hints_np[:stored_coarse_candidate_count], candidate_ngram_hints_buffer)
                cl.enqueue_copy(queue, candidate_periodic_hints_np[:stored_coarse_candidate_count], candidate_periodic_hints_buffer)
                cl.enqueue_copy(queue, candidate_displacement_hints_np[:stored_coarse_candidate_count], candidate_displacement_hints_buffer)
                cl.enqueue_copy(queue, candidate_best_displacements_np[:stored_coarse_candidate_count], candidate_best_displacements_buffer)
                cl.enqueue_copy(queue, candidate_layer_hints_np[:stored_coarse_candidate_count], candidate_layer_hints_buffer)
                cl.enqueue_copy(queue, candidate_eligibility_np[:stored_coarse_candidate_count], candidate_eligibility_buffer)
                queue.finish()

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
                    for index in range(stored_coarse_candidate_count)
                    if bool(candidate_eligibility_np[index])
                ]
                qualified_candidate_count = len(raw_candidates)
                total_qualified_candidates += qualified_candidate_count
                raw_candidates = sort_raw_candidate_entries(raw_candidates)[: config["match_limit"]]
                stored_candidate_count = len(raw_candidates)
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
                            displacement_window=24,
                            route_followup_limit=3,
                        )
                    )
                pass_candidates = dedupe_candidate_records(pass_candidates)
                focus_candidates = run_focus_followup(
                    pass_candidates,
                    base_squares=base_squares,
                    max_post_key_length=config["max_post_key_length"],
                    displacement_window=24,
                    route_followup_limit=3,
                    focus_budget=config["focus_budget"],
                    focus_seed_limit=config["focus_seed_limit"],
                    focus_neighbor_span=config["focus_neighbor_span"],
                )
                focused_candidate_count = len(focus_candidates)
                total_focused_candidates += focused_candidate_count
                if focus_candidates:
                    pass_candidates = dedupe_candidate_records([*pass_candidates, *focus_candidates])
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
                    "coarse_candidate_count": coarse_candidate_count,
                    "qualified_candidate_count": qualified_candidate_count,
                    "coarse_stored_candidate_count": stored_coarse_candidate_count,
                    "coarse_overflow_count": coarse_overflow_count,
                    "stored_candidate_count": stored_candidate_count,
                    "hydrated_candidate_count": hydrated_candidate_count,
                    "focused_candidate_count": focused_candidate_count,
                    "launch_global_work_items": int(global_work_shape[0]),
                    "launch_local_size": int(local_work_shape[0]) if local_work_shape is not None else None,
                    "top_candidates": pass_candidates[: config["top_candidate_limit"]],
                    "elapsed_seconds": elapsed,
                }
            )

            if not args.json:
                print(
                    f"Pass {pass_number}: attempts={pass_decryptions:,}, "
                    f"exact_matches={pass_exact_match_count}, coarse={coarse_candidate_count}, "
                    f"qualified={qualified_candidate_count}, hydrated={hydrated_candidate_count}, focused={focused_candidate_count}, elapsed={elapsed:.4f}s"
                )

            pass_number += 1
    except KeyboardInterrupt:
        if not args.json:
            print("Sweep interrupted by user.")

    overall_top_candidates = dedupe_candidate_records(overall_candidates)[: config["top_candidate_limit"]]
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
            "coarse_buffer_limit": coarse_buffer_limit,
            "coarse_retained_limit": coarse_retained_limit,
            "score_threshold": config["score_threshold"],
            "hydrate_limit": config["hydrate_limit"],
            "min_anchor_hits": config["min_anchor_hits"],
            "focus_budget": config["focus_budget"],
            "focus_seed_limit": config["focus_seed_limit"],
            "focus_neighbor_span": config["focus_neighbor_span"],
            "launch_global_work_items": int(global_work_shape[0]),
            "launch_local_size": int(local_work_shape[0]) if local_work_shape is not None else None,
            "qualified_candidate_count": total_qualified_candidates,
            "hydrated_candidate_count": total_hydrated_candidates,
            "focused_candidate_count": total_focused_candidates,
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
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
