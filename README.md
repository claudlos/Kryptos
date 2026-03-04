# Kryptos K4 Decryption Suite

A Python and OpenCL based repository containing a suite of tools designed to analyze and attempt to crack the final unsolved section (K4) of the famous Kryptos sculpture at the CIA headquarters.

## Overview

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
