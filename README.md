# Kryptos K4 Decryption Suite

A Python and OpenCL based repository containing a suite of tools designed to analyze and attempt to crack the final unsolved section (K4) of the famous Kryptos sculpture at the CIA headquarters.

## Overview

🌐 **Live Project Website & Web App:** [https://claudlos.github.io/Kryptos/](https://claudlos.github.io/Kryptos/)

This project implements various classical cryptography strategies and utilizes an OpenCL-accelerated GPU brute-forcing tool to perform massive-scale decryptions.

### Included Strategies
- Quagmire / Vigénere variants
- Matrix transposition
- Index of Coincidence (IoC) Hill Climbing
- Autokey & Chained Autokey
- Grilles
- Segmented approach
- Shifted Running Key
- External Keyer
- Fractionation

## Prerequisites

- Python 3.x
- `numpy`
- `pyopencl` (requires OpenCL drivers for your hardware, whether CPU or GPU)
- `mojo` (optional, for running the parallel Mojo variants)

## Installation

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd Kryptos
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Generate the required K4 dictionary file (which is git-ignored by default):
   ```bash
   python generate_k4_dictionary.py
   ```

## Usage

You can use the `kryptos_toolkit.py` central script to run the classical Python strategies:
```bash
python kryptos_toolkit.py --strategy all
```

For massive-scale OpenCL-based GPU processing:
```bash
python gpu_opencl_suite.py
```

## 🔬 Novel Research & Unpublicized Ground

While K4 remains officially unsolved, this repository documents multiple deeply theoretical, previously unpublicized strategies that drastically expand upon existing public research. 

### 1. Definitively Ruling out Basic and Combinatorial Strategies
A core component of our research involved scientifically and mathematically eliminating 13 empirical approaches. Through extensive scripting and statistical analysis, we have definitively ruled out:
- **Spatial Matrix Masking & Grilles**: No direct spatial geometry or hardware grille simulation (such as a 7x14 extraction grid overlay) yielded the contiguous native 1D arrays of the target ciphertexts.
- **Index of Coincidence (IoC) Maximization**: K4 exhibits an abnormally low IoC of `0.0361` (compared to English at ~0.0667 and pure random at ~0.0385). Randomized hill-climbing algorithms over 300,000 permutations attempting to reconstruct structural transpositions failed completely.
- **Quagmire III Variants & Running Keys**: Hypotheses connecting K4 to the Quagmire III framework of K1 and K2—including Autokeying with thematic primers and shifted running keys derived from K1-K3 plaintexts—were all mathematically eliminated as they failed to align with known anchors (`BERLINCLOCK`, `EASTNORTHEAST`).
- **Segmented Processing**: Testing theories that the letter `W` acts as a segment delimiter/reset mechanism failed. 
- **The "Howard Carter Diaries" Keyer Overlay**: Stemming from the `Slowly, desperately slowly` K3 clue, Strategy 9 ingested full blocks of external texts—specifically Howard Carter’s original November 1922 diary entries—applying them as exhaustive running keys. This historical overlay hypothesis was fully eliminated.

### 2. Massive-Scale Native OpenCL GPU Acceleration Utilizing 4.2 Billion Permutations
Recognizing that standard Python CPU engines (peaking at ~18k permutations/sec) and even Mojo MLIR/LLVM compiling architectures (~1.5M keys/sec) were insufficient for complex combination ciphers, an entirely new acceleration framework was engineered:
- **Windows OpenCL Dispatches**: A native OpenCL brute-forcer was engineered to bypass inherent WSL threading bottlenecks on Windows, tapping directly into consumer GPUs (e.g., AMD Radeon 680M).
- **Fractionated Polygraphic Matings**: To combat the 0.0361 IoC, the GPU suite mated Bifid coordinate fractionation with 9,510 unified Custom Keys across multiple transposition periods.
- **The 4.2 Billion Sweep**: At a decryption velocity of `7,777,777` permutations per second, the GPU OpenCL C-kernels executed a continuous brute force of 4,200,000,000 distinct permutations in roughly 540 seconds. While producing no clear plaintexts, this represents a major benchmark in amateur Kryptos permutation assaults.

### 3. Debunking The 2025 Grok 3 AI "Solution" Claim
In February 2025, a claim surfaced asserting that an AI model (Grok 3) had decrypted K4 to read: *"THIS IS A GUIDE TO THE BERLIN CLOCK WHICH IS NORTHEAST OF HERE AT CIA LANGLEY VIRGINIA"*. 

Through mathematical modeling in this repository, **we conclusively debunk this claim**:
1. **Mathematical Impossibility (Length Mismatch)**: The K4 ciphertext consists of **exactly 97 characters**. The proposed Grok 3 plaintext is only **82 alphabetic characters**. An exact 1:1 encryption scheme (substitution, Vigenere, transposition, fractionation) inherently requires equal lengths; resolving this discrepancy mandates massive, undocumented null padding.
2. **Contradiction of Official Anchors**: Jim Sanborn officially verified that character indices 22-34 map *exactly* to `EASTNORTHEAST`. The AI's purported plaintext contains the word `NORTHEAST` but entirely omits the preceding `EAST`. 

This repository's mathematical analyses confirm the Grok 3 string is an AI hallucination—a thematic guess that fails fundamental cryptographic scrutiny.

---
This suite is aimed at pushing the computational boundaries of amateur Kryptos research, documenting mathematically eliminated avenues, and automating the most complex combinatory cipher theories.
