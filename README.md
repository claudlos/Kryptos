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
While K4 remains officially unsolved, this repository contains several deeply theoretical and previously unpublished strategies that expand upon current public research. Our new ground includes:

- **Massive-Scale GPU Processing Restrictions Bypassed**: We constructed an OpenCL brute-forcer designed specifically to target 4.2 billion permutations spanning complex polyalphabetic and mixed-alphabet keys on consumer GPUs (e.g., AMD Radeon 680M), bypassing inherent WSL processing bottlenecks on Windows.
- **Dynamic Segmented Autokey Chaining**: Rather than treating K4 as a monolithic cipher, we hypothesize (and coded strategies for) nested, dual-layer autokeys separated by the `W` characters, potentially acting as segment resets.
- **The "Howard Carter Diaries" Keyer Overlay**: Stemming from the `Slowly, desperately slowly` K3 clue, we wrote tools (Strategy 9) to ingest large blocks of external texts—such as Howard Carter’s original November 1922 diary entries—and employ them as exhaustive running keys over a shifted matrix, factoring in the recently hypothesized `BERLINCLOCK` and `EASTNORTHEAST` plaintext anchors.
- **Fractionated Quagmire Mating**: A combination of Bifid/Fractionation with the baseline K1/K2 Quagmire III algorithms, directly aimed at the unusually low 0.0361 Index of Coincidence.

This suite is meant to push the computational boundaries of amateur Kryptos research and automate the most complex layering theories.
