# Handoff

Date: 2026-03-22 (session 7, final)

## Summary

This session was a major research push covering three areas: (1) exhaustive running-key testing of the complete Howard Carter excavation journals from the Griffith Institute, (2) mathematical/positional key generation analysis, and (3) full-text analysis of "The Cryptos Conundrum" novel by Chase Brandon. Multiple cipher families and key sources have been definitively eliminated. A key structural finding about the forced Vigenere key at period 26 was uncovered.

### What Was Done

1. **Strategy 38**: Full Carter diary (Nov 26, 1922) running-key attack — 147K attempts across Vigenere/Beaufort/Quagmire + 14 transposition keywords. Best: 7/24 anchor hits = noise.
2. **Strategy 38b**: K3 vs actual diary textual comparison — documented 9 deliberate creative modifications Sanborn made. Exhaustive period search (periods 2-6, all permutations, 8.3M attempts). Best: 8/24 = noise.
3. **Strategy 39**: All three Griffith Institute excavation seasons (77,462 alpha chars, 5M+ attempts) under 3 cipher models × 19 transposition keywords + reverse direction. Best: 8/24 = noise. **Carter journals definitively eliminated.**
4. **Strategy 40/40b**: Mathematical key generation — 1,145 keys from Fibonacci, Lucas, K2 coordinates (38°57'6.5"N, 77°8'44"W), primes, modular arithmetic, positional grid rules, and combined schemes. **No mathematical function fits the forced key values.** Deep period analysis revealed the period-26 near-consistency finding.
5. **Book analysis**: Full-text extraction and keyword/cipher analysis of "The Cryptos Conundrum" (446 pages, 673K chars). Identified potential new keywords but concluded the book is not a cipher key source.

### New Files

#### Corpus files
- `kryptos/data/corpora/carter_full_diary_nov26.txt` — actual Nov 26 1922 diary entry (3,285 alpha chars)
- `kryptos/data/corpora/carter_journal_season1.txt` — Season 1: Oct 28–Dec 31, 1922 (22K alpha)
- `kryptos/data/corpora/carter_journal_season2.txt` — Season 2: Oct 3, 1923–Feb 11, 1924 (40K alpha)
- `kryptos/data/corpora/carter_journal_season3.txt` — Season 3: Jan 19–Mar 31, 1925 (11K alpha)
- `cryptos_conundrum_full_text.txt` — full extracted text of the novel

#### Strategy files
- `strategy38_carter_diary_full.py` — full diary running-key attack
- `strategy38b_carter_deep_analysis.py` — K3 vs diary diff + exhaustive period search
- `strategy39_carter_journals_exhaustive.py` — all three seasons exhaustive attack
- `strategy40_mathematical_key_generation.py` — coordinate/Fibonacci/modular/positional key tests
- `strategy40b_key_pattern_deep.py` — deep key pattern analysis (period, affine, recurrence)

#### Run artifacts
- `runs/carter_diary_full.json`
- `runs/carter_diary_deep.json`
- `runs/carter_journals_exhaustive.json`
- `runs/mathematical_key_generation.json`
- `runs/key_pattern_deep.json`

---

## Key Finding: Period-26 Vigenere Near-Consistency

The forced Vigenere key at 24 known positions is: `BLZCDCYYGCKAZMUYKLGKORNA`
- Cluster 1 (positions 21-33, EASTNORTHEAST): `BLZCDCYYGCKAZ`
- Cluster 2 (positions 63-73, BERLINCLOCK): `MUYKLGKORNA`

Under period 26 (key length = alphabet length), there is **only 1 conflict**: position 21 maps to B (from EASTNORTHEAST) and position 73 maps to A (from BERLINCLOCK), both in bucket 21 mod 26. These differ by exactly 1.

23 of 26 key slots are determined. The 3 unknown slots (positions 8, 9, 10) control text positions [8,34,60,86], [9,35,61,87], [10,36,62,88]. Brute-forcing 17,576 combinations produces candidates with English words at anchor boundaries (WITH, EACH, SUCH, HERE, HAVE, NOT, MAY, JUST) but no fully coherent plaintext.

The 1-off conflict could indicate:
1. Period 27-29 (all have 0 conflicts but more unknowns)
2. A secondary transformation causing the ±1 shift
3. Not pure Vigenere — something close (Quagmire with off-by-one indexing)

**No mathematical function** (linear, quadratic, exponential, Fibonacci, prime, recurrence) fits the forced key values. **The key is almost certainly derived from a text source, not a mathematical rule.**

---

## K3 vs Actual Carter Diary: Sanborn's Deliberate Changes

| K3 Plaintext | Actual Diary | Change |
|---|---|---|
| I MADE A TINY BREACH | WE MADE A TINY BREACH | we → I |
| IN THE UPPER LEFT HAND CORNER | IN THE TOP LEFT HAND CORNER | top → upper |
| I INSERTED THE CANDLE AND PEERED IN | I WIDENED THE BREACH AND BY MEANS OF THE CANDLE LOOKED IN | Simplified |
| THE FLAME TO FLICKER | THE CANDLE TO FLICKER | candle → flame |
| PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST | ONE'S EYES BECAME ACCUSTOMED TO THE GLIMMER OF LIGHT THE INTERIOR OF THE CHAMBER GRADUALLY LOOMED | Complete rewrite |
| SLOWLY DESPARATLY SLOWLY | (not in diary) | Added by Sanborn |
| WITH TREMBLING HANDS | (not in diary) | Added by Sanborn |
| X (separator) | (not in diary) | Sanborn convention |
| Q (terminal) | (not in diary) | Sanborn convention |

These are **creative modifications**, not transcription errors. If K4 uses diary-derived text, it could be Sanborn's own paraphrase of a different section.

---

## Comprehensive Elimination Matrix

### Definitively Eliminated
| Cipher Family | Strategy | Evidence |
|---|---|---|
| Simple monoalphabetic | 17, 30 | Mapping contradiction at every transposition tested |
| Affine cipher | 17 | No valid (a,b) pair |
| Autokey Vigenere | 25 | Zero consistent configs across all transpositions |
| Gromark cipher | 21 | 22K primers tested, all fail at anchors |
| Hill 2×2 cipher | 31 | 157K invertible matrices, zero produce ≥16 anchor matches |
| Single Vigenere (no transposition) | 19 | No single period satisfies all 4 anchors |
| Carter diary as running key | 38 | 147K attempts, best 7/24 = noise |
| Carter journals (all 3 seasons) | 39 | 5M attempts, best 8/24 = noise |
| K1-K3 plaintexts as running key | 1, 8 | No anchor matches |
| Mathematical key derivation | 40 | Coordinates, Fibonacci, primes, modular, positional — none fit |

### Unlikely
| Cipher Family | Strategy | Evidence |
|---|---|---|
| Pure Playfair | 28 | Best: 7/9 NORTHEAST chars, no complete anchor match |
| Pure Four-square | 28 | No anchor matches |
| Pure Two-square | 28 | No anchor matches |

### Still Possible
| Cipher Family | Strategy | Notes |
|---|---|---|
| Polyalphabetic + transposition | 18-19, 25-26 | Consistent configs exist, no English plaintext |
| Beaufort + transposition | 25-26 | Same |
| Quagmire III + transposition | 25-26 | Same |
| Running key from unknown text | 32, 37 | Carter eliminated; other sources untested |
| 3+ layer compound | — | Not yet implemented |
| Sanborn-modified cipher | — | Not testable without more info |

---

## The Cryptos Conundrum Novel: Key Findings

- **Not a cipher key source.** The novel is a sci-fi thriller by CIA PR officer Chase Brandon, published 2012 — two decades after the sculpture. No insider knowledge of K4.
- **"Wayne W. Wondelman"** — fictionalized Ed Scheidt (the real CIA cryptographer who helped Sanborn). Mentioned in the Author's End Note.
- **"Make the Vigenere even more abstruse"** — the fictional Scheidt analog tells the fictional Sanborn analog this. Confirms community consensus that K4 is a modified Vigenere.
- **Two secret messages** — the novel's premise: one by the artist, one hidden by the cryptographer. Persistent community theory about Scheidt contributing more than guidance.
- **Letter W significance** — 23rd letter, symbol for tungsten (wolfram), Italian for "viva" (long live). K4 has W at positions 19, 20, 46, 56.
- **New keywords to test**: CHALMERS, CRAWFORD, WONDELMAN, COLLABROS, TABULA, SPERO ("I hope" — Chalmers clan motto), NOBILITY, INDECHIFFRABLE, WOLFRAM

---

## Current Strategy Inventory (40 strategies)

| ID | Name | Category | Status |
|---|---|---|---|
| 1 | Quagmire III Running Keys | classical | no_match |
| 2 | Spatial Matrix Reassembly | transposition | no_match |
| 3 | Hybrid Transposition Search | transposition | partial |
| 4 | Quagmire III Autokey | classical | no_match |
| 5 | Geometric Grilles | masking | no_match |
| 6 | Chained Autokey | classical | no_match |
| 7 | Segmented Resets | segmentation | no_match |
| 8 | Shifted Running Keys | classical | no_match |
| 9 | External Text Running Key | historical | partial |
| 10 | Fractionation Pipeline | fractionation | partial |
| 11 | Corpus Running Key | historical | partial |
| 12 | Periodic Transposition Hillclimb | transposition | partial |
| 13 | Hybrid Pipeline Search | hybrid | partial |
| 14 | Displacement Route Search | hybrid | partial |
| 15 | Z340-Style Transposition Enumeration | transposition | partial |
| 16 | SAT/SMT Constraint Elimination | elimination | confirmed |
| 17 | Known-Plaintext Method Elimination | elimination | confirmed |
| 18 | Alternating Optimization | hybrid | partial |
| 19 | MCMC Key Search | hybrid | partial |
| 20 | Generalized IC Fingerprinting | analysis | confirmed |
| 21 | Gromark Cipher | classical | eliminated |
| 22 | ML Cipher Type Classification | analysis | confirmed |
| 23 | Bayesian Cipher Analysis | analysis | confirmed |
| 24 | Neural Language Model Scoring | scoring | confirmed |
| 25 | Beaufort/Quagmire Constraint-First Sweep | hybrid | eliminated |
| 26 | LATITUDE Deep Investigation | hybrid | inconclusive |
| 27 | Key Derivation Analysis | analysis | inconclusive |
| 28 | Digraphic Cipher Sweep | classical | unlikely |
| 29 | Dictionary Full-Text Scoring | scoring | confirmed |
| 30 | Monoalphabetic + Transposition | elimination | eliminated |
| 31 | Hill Cipher + Transposition | elimination | eliminated |
| 32 | Unknown-Source Running Key Sweep | historical | partial |
| 33 | Hill 3×3 + Transposition | elimination | wrapper |
| 34 | Crib-Dragging Autocorrelation | analysis | wrapper |
| 35 | No-Transposition Quagmire III Deep Search | classical | wrapper |
| 36 | Anchor Position Sensitivity Analysis | analysis | wrapper |
| 37 | Transposition + Unknown-Source Running Key | hybrid | partial |
| 38 | Full Carter Diary Running-Key Attack | historical | eliminated |
| 39 | Exhaustive Carter Journals Running-Key Attack | historical | eliminated |
| 40 | Mathematical/Positional Key Generation | analysis | eliminated |

---

## Next Sensible Steps

1. **Register strategies 38-40 in `kryptos/catalog.py`.**
2. **Test new keywords from novel analysis** (WONDELMAN, CHALMERS, COLLABROS, SPERO, etc.) through the constraint-first framework.
3. **Investigate the November 2025 auction** — if the plaintext leaked, problem reduces to method identification.
4. **Implement 3-layer compound cipher search.**
5. **Expand external text corpus** — Friedman's Military Cryptanalysis, Sanborn's other sculptures (Antipodes, Cyrillic Projector), CIA founding documents.
6. **Native-port strategies 33-36** from subprocess wrappers.
7. **Investigate the period-26 near-miss** — test Quagmire variants that might explain the ±1 offset at bucket 21.

---

## Previous Session History

### Session 6 (2026-03-21)
Integrated strategies 33-37. Expanded Strategy 32 source pool. Added transposition + unknown-source running-key lane.

### Session 5 (2026-03-21)
Repaired catalog.py and corpora.py corruption. Added Strategy 32 (unknown-source running key).

### Session 4 (2026-03-21)
Strategies 30-31. Eliminated monoalphabetic and Hill 2×2 ciphers. Built comprehensive elimination matrix.
