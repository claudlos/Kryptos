# Kryptos K4 Research Summary

Last updated: 2026-03-22

## The Problem

Kryptos is a sculpture by Jim Sanborn at CIA headquarters in Langley, Virginia, dedicated in 1990. It contains four encrypted messages. Three have been solved. The fourth, K4, is 97 characters of unsolved ciphertext — one of the most famous open problems in cryptanalysis.

```
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
```

### What We Know For Certain

- **24 known plaintext characters** from clues released by Sanborn:
  - Positions 22-34: `EASTNORTHEAST` (released 2010/2020)
  - Positions 64-74: `BERLINCLOCK` (released 2014/2020)
- **Index of Coincidence**: 0.0361 — below random (0.0385), far below English (0.0667)
- **K1 and K2** used Quagmire III cipher with keywords PALIMPSEST, ABSCISSA and the KRYPTOS mixed alphabet
- **K3** used a different method (transposition), paraphrasing Howard Carter's Nov 26, 1922 diary
- **Ed Scheidt** (CIA cryptographer) assisted Sanborn with "basic code construction"
- **Context clues** (2025 Sanborn open letter): Egypt 1986, Berlin Wall, World Clock, delivering a message
- **Meta clues**: K5 follows K4, K5 uses similar system, K5 repeats BERLINCLOCK in same position

### The KRYPTOS Mixed Alphabet

```
KRYPTOSABCDEFGHIJLMNQUVWXZ
```
Standard alphabet reordered by keyword KRYPTOS (J omitted, then remaining letters).

---

## What We Have Built

### 40 Cryptanalytic Strategies

A structured Python toolkit with 40 strategies spanning classical ciphers, transposition enumeration, constraint satisfaction, MCMC search, Bayesian analysis, ML classification, neural scoring, running-key attacks, and mathematical key generation. Each strategy produces structured JSON output with anchor scores, language metrics, and candidate rankings.

### Supporting Infrastructure

- **GPU pipeline**: OpenCL Bifid sweep at ~7.8M candidates/sec
- **Benchmark system**: Profiles for GPU, CPU, and Mojo runners
- **Corpus library**: Howard Carter journals (all 3 Griffith Institute seasons), solved-panel references, domain-specific word lists
- **Dashboard**: Static site at https://claudlos.github.io/Kryptos/ backed by generated JSON
- **Google Colab workbench**: Notebook for cloud GPU runs

---

## What We Have Eliminated

### Cipher Families (Definitively Ruled Out)

| Cipher | Evidence | Strategy |
|--------|----------|----------|
| **Simple monoalphabetic** | Mapping contradiction at known positions for every transposition tested (0/13,136 configs consistent) | 17, 30 |
| **Affine cipher** | No valid (a,b) pair satisfies the 24 known positions | 17 |
| **Autokey Vigenere** | Zero consistent configurations across all transpositions | 25 |
| **Gromark cipher** | 22,000 primers tested (2-5 digit seeds), all fail at anchors | 21 |
| **Hill 2×2 cipher** | All 157,248 invertible 2×2 matrices tested, zero produce ≥16 anchor matches | 31 |
| **Single Vigenere (no transposition)** | No single period satisfies all 4 anchor groups simultaneously | 19 |

### Key Sources (Definitively Ruled Out)

| Source | Attempts | Best Result | Strategy |
|--------|----------|-------------|----------|
| **K1-K3 plaintexts as running key** | Direct test | No anchor matches | 1, 8 |
| **Carter diary (Nov 26, 1922)** | 147K attempts (3 models × 14 transpositions) | 7/24 = noise | 38 |
| **Carter journals (all 3 seasons)** | 5M+ attempts (77K alpha chars × 3 models × 19 transpositions) | 8/24 = noise | 39 |
| **Mathematical key derivation** | 1,145 key functions (Fibonacci, coordinates, primes, modular, positional) | 7/24 = noise | 40 |

### Key Source Statistical Baseline

Each anchor position has a 1/26 chance of random match. With 24 positions, the expected number of random matches per trial is ~0.92. Across millions of trials, observing 8/24 hits is well within the noise floor. A genuine signal requires 12+ hits from a single source, 16+ to be convincing.

### Cipher Families (Unlikely but Not Proven Impossible)

| Cipher | Evidence |
|--------|----------|
| Pure Playfair | Best: 7/9 NORTHEAST chars, no complete anchor match. Also K4 has 97 chars (odd, incompatible with Playfair) and double letters (BB, SS). |
| Pure Four-square | No anchor matches |
| Pure Two-square | No anchor matches |

---

## What Remains Possible

### 1. Polyalphabetic + Transposition (Leading Hypothesis)

Vigenere, Beaufort, or Quagmire III combined with a columnar transposition layer. The constraint-first framework finds thousands of consistent (transposition, substitution) configurations, but none produce readable English outside the anchor positions. The key source remains unknown.

**The LATITUDE keyword** produces the highest-scoring transposition, but all substitution models after LATITUDE yield noise.

### 2. Running Key from an Unidentified Text

The forced Vigenere key values look random (no mathematical pattern), which is exactly what a running key from natural text would produce. Carter's journals are eliminated. Untested sources include:
- Friedman's "Military Cryptanalysis" (Scheidt cited this explicitly)
- Sanborn's other sculpture inscriptions (Antipodes, Cyrillic Projector)
- CIA founding documents, dedication speeches
- Text from the Kryptos courtyard (Morse code side, compass rose)
- Sanborn's own creative paraphrases (as he did with K3)

### 3. Sanborn-Modified Cipher

Something close to but not exactly standard Vigenere. The "Cryptos Conundrum" novel's fictionalized Scheidt says "I believe we can make the Vigenère even more abstruse." The period-26 near-consistency with its ±1 offset could indicate a Quagmire variant with nonstandard alphabet indexing.

### 4. Three or More Layers

Every two-layer combination (transposition + substitution) has been searched. A third layer (fractionation, additional transposition, or scrambling step) has not been tested.

---

## Key Analytical Findings

### The Forced Key Values

Under a Vigenere model, the 24 known plaintext characters force specific key values:

```
Position: 21 22 23 24 25 26 27 28 29 30 31 32 33
CT:        F  L  R  V  Q  Q  P  R  N  G  K  S  S
PT:        E  A  S  T  N  O  R  T  H  E  A  S  T
Key:       B  L  Z  C  D  C  Y  Y  G  C  K  A  Z

Position: 63 64 65 66 67 68 69 70 71 72 73
CT:        N  Y  P  V  T  T  M  Z  F  P  K
PT:        B  E  R  L  I  N  C  L  O  C  K
Key:       M  U  Y  K  L  G  K  O  R  N  A
```

**Full forced key**: `BLZCDCYYGCKAZMUYKLGKORNA`

### Period-26 Analysis

With period 26 (key length = full alphabet), only **1 conflict** exists: position 21 yields B, position 73 yields A (both bucket 21 mod 26, differing by 1). Twenty-three of 26 key slots are determined, with 3 unknowns.

Periods 27, 28, and 29 have **zero conflicts** but 3-5 unknown slots each.

### No Mathematical Pattern

The forced key values do not satisfy any:
- Linear function: `key = a*pos + b (mod 26)` — zero solutions
- Quadratic function: `key = a*pos² + b*pos + c (mod 26)` — zero solutions
- Exponential function: `key = base^pos (mod 26)` — no match
- Fibonacci/Lucas recurrence — no match
- K2 coordinate derivation — no match
- Linear recurrence (order 2 or 3) within either cluster — zero solutions
- Cross-cluster recurrence prediction — zero matches ≥3

**Conclusion: The key is almost certainly derived from a text source, not a mathematical process.**

### K3 vs Carter Diary

Sanborn made **9 deliberate creative modifications** when adapting the Howard Carter diary for K3:
1. Changed `we` → `I` (pronoun)
2. Changed `top` → `upper`
3. Changed `candle` → `flame`
4. Simplified the "widened the breach" passage
5. Added `SLOWLY DESPARATLY SLOWLY` (with his misspelling)
6. Added `WITH TREMBLING HANDS`
7. Completely rewrote the "eyes accustomed to glimmer" passage
8. Used `X` as separator (not in diary)
9. Appended `Q` at the end

These are creative choices, not transcription errors. This means if K4's key source is text-derived, it could be Sanborn's own paraphrase rather than a verbatim source.

### IC Analysis

| Metric | K4 Value | English | Random |
|--------|----------|---------|--------|
| IC | 0.0361 | 0.0667 | 0.0385 |

K4's IC is **below random**, suggesting either a highly polyalphabetic cipher (long/random key) or multi-layer encryption that flattens frequencies beyond what a single substitution would produce.

---

## "The Cryptos Conundrum" Novel Analysis

Chase Brandon's 2012 novel (446 pages) was fully extracted and analyzed. Key findings:

- **Not a key source.** Brandon was CIA PR, not a cryptographer. Published 22 years after the sculpture.
- **"Wayne W. Wondelman"** — fictionalized Ed Scheidt in the Author's End Note
- **"Make the Vigenère even more abstruse"** — confirms modified-Vigenere hypothesis
- **"Two secret messages"** — one by the artist, one by the cryptographer
- **Letter W obsession** — 23rd letter, tungsten/wolfram, Italian "viva" (long live)
- **New potential keywords**: WONDELMAN, CHALMERS, CRAWFORD, COLLABROS, TABULA, SPERO, NOBILITY, INDECHIFFRABLE, WOLFRAM

---

## Repository Structure

```
kryptos_toolkit.py           — primary CLI for running strategies
k4_analyzer.py               — clue-position and shift analysis
gpu_opencl_suite.py           — OpenCL Bifid sweep
strategy{01-40}*.py           — individual strategy implementations
kryptos/                      — shared library (constants, scoring, catalog, models)
kryptos/data/corpora/         — corpus files (Carter journals, word lists)
tests/                        — unittest coverage
docs/                         — static dashboard site
runs/                         — structured JSON run artifacts
notebooks/                    — Colab workbench
```

---

## How to Contribute

1. Read `HANDOFF.md` for current state and next steps
2. Run `python kryptos_toolkit.py --list-strategies` to see all 40 strategies
3. Run a specific strategy: `python kryptos_toolkit.py --strategy N --json`
4. Run the full suite: `python kryptos_toolkit.py --strategy all --output runs/latest_run.json`
5. Add a new strategy following the pattern in `kryptos/catalog.py`
6. The `kryptos/constants.py` file has all anchor data and known-plaintext mappings

---

## References

- [Kryptos Wikipedia](https://en.wikipedia.org/wiki/Kryptos)
- [Griffith Institute Carter Journals](http://www.griffith.ox.ac.uk/gri/4sea1not.html)
- [kryptosfan.com](https://kryptosfan.com/)
- [r/kryptos](https://www.reddit.com/r/kryptos/)
- George Lasry PhD thesis (alternating optimization for compound ciphers)
- Hauer et al., NAACL 2024 (Bayesian classical cipher analysis)
- Z340 solution methodology (Blake, Oranchak, Van Eycke, 2020)
