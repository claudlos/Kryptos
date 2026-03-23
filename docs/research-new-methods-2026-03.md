# New Methods Research Brief — March 2026

## Context

Your current toolkit (strategies 1-14) covers Quagmire variants, matrix
reassembly, IoC hillclimb, autokey, grilles, segmented resets, shifted/external
running keys, fractionation pipelines, corpus running keys, periodic
transposition hillclimb, hybrid pipeline search, and displacement route search.
GPU pipeline uses OpenCL with anchor scoring, n-gram hints, periodic structure
fingerprints, and displacement metadata.

This document identifies methods NOT already in your toolkit that are worth
implementing, ordered by expected impact.

---

## ① Z340-Style Systematic Transposition Enumeration + Automated Solving

**Why it matters:** The Zodiac 340 cipher resisted 51 years because solvers
tried substitution OR transposition but not the layered combination. It was
cracked in Dec 2020 by Sam Blake, David Oranchak, and Jarl Van Eycke using:

  1. Systematic enumeration of transposition reading patterns
  2. For each candidate transposition, feed the unscrambled text into
     AZDecrypt's hill-climbing solver (n-gram scoring)
  3. The correct transposition produced readable English after substitution
     solving

**What's new for your project:** Your current strategies mostly pick a cipher
family and search within it. This approach INVERTS the problem: enumerate ALL
plausible transposition patterns (route ciphers, periodic, columnar, diagonal,
spiral, boustrophedon, multiple-region) and for EACH one, run your existing
substitution solvers on the result. The outer loop is transposition enumeration;
the inner loop is substitution recovery.

**Implementation sketch:**
- Generate a library of transposition pattern generators (route variants,
  columnar with various key lengths, rail fence, myszkowski, etc.)
- For each transposition T: compute T_inverse(K4_ciphertext)
- Score the result with your existing anchor scorer + n-gram language model
- Parallelize on GPU: enumerate transpositions on CPU, score on GPU
- K4's known plaintext (19/97 chars) provides a MUCH stronger filter than
  Z340 had — most transpositions will immediately fail the anchor check

**Estimated effort:** Medium. You already have the scoring infrastructure.
Main work is building the transposition enumeration library.


## ② MCMC (Markov Chain Monte Carlo) Key Search

**Why it matters:** MCMC is fundamentally different from hill climbing. Instead
of greedily pursuing better scores, it samples from the posterior distribution
over keys, accepting worse solutions probabilistically. This means:

  - It naturally escapes local optima that trap hill climbers
  - It can explore multiple modes of the solution space simultaneously
  - It provides a principled way to quantify uncertainty about key hypotheses

**Key references:**
- Persi Diaconis, "The Markov Chain Monte Carlo Revolution" — foundational
  paper applying Metropolis-Hastings to substitution cipher breaking
- "MCMC Methods for Decrypting Civil War Ciphers" (AMSTAT 2020) — extends
  MCMC to transposition ciphers specifically
- Practical Cryptography MCMC tutorial (practicalcryptography.com)

**Implementation sketch:**
- State: a candidate key (substitution mapping + transposition permutation)
- Proposal: swap two elements in the key
- Acceptance: Metropolis-Hastings ratio using n-gram log-likelihood as the
  energy function
- Modification for K4: add HARD CONSTRAINTS from known plaintext — reject
  any proposal that violates BERLINCLOCK/NORTHEAST positions
- Run multiple chains with different initializations
- Convergence diagnostic: Gelman-Rubin R-hat across chains

**Why this differs from your current approach:** Your GPU pipeline does
brute-force enumeration with scoring. MCMC is a guided random walk that
concentrates sampling effort in high-probability regions of key space.
It's particularly valuable for the substitution layer where 26! is too large
for exhaustive search.

**Estimated effort:** Medium. Python implementation is straightforward.
GPU acceleration possible but the algorithm is inherently sequential per chain.


## ③ Bayesian Cipher Analysis (NAACL 2024)

**Why it matters:** "On Bayesian Analysis of Classical Ciphers" (Hauer et al.,
NAACL 2024 Findings) demonstrated full key recovery for substitution and
Vigenere ciphers using Bayesian posterior inference. This is a rigorous
probabilistic framework that naturally incorporates:

  - Prior knowledge about key structure (e.g., key derived from a word)
  - Known plaintext as likelihood evidence
  - Language model as prior on plaintext

**What's new:** Instead of scoring a single candidate (your current approach),
Bayesian analysis maintains a full distribution over keys. This lets you:

  - Identify which parts of the key are well-determined vs uncertain
  - Focus search effort on the uncertain dimensions
  - Combine evidence from multiple cipher layers properly

**Implementation:**
- Use PyMC or NumPyro for Bayesian modeling
- Define prior over key space (uniform or keyword-seeded)
- Define likelihood using n-gram language model
- Condition on known plaintext at anchor positions
- Run NUTS or HMC sampler (continuous relaxation) or Gibbs (discrete)
- Examine posterior marginals to identify well-constrained key dimensions

**Estimated effort:** Medium-high. Requires probabilistic programming setup.


## ④ Constraint Propagation + SAT/SMT Solving

**Why it matters:** Your known plaintext (EASTNORTHEAST at 22-34, BERLINCLOCK
at 64-74) creates HARD CONSTRAINTS that can dramatically prune the search
space before any metaheuristic search begins.

**For transposition layer:**
- If K4 uses columnar transposition with period p, the known plaintext
  positions must map correctly under the column permutation
- This creates a constraint satisfaction problem (CSP) solvable by Z3
- For most period values, the constraints from 19 known positions will
  leave very few valid permutations

**For substitution layer:**
- Known plaintext gives us partial key information
- If Vigenere with period p: key[i] is determined at 19 positions mod p
- Propagate: if multiple known positions share the same key index (mod p),
  they must produce the same key letter — this is an immediate consistency
  check

**For combined layers:**
- Encode outer(inner(plaintext)) = ciphertext as SMT constraints
- Let Z3 find satisfying assignments or prove unsatisfiability
- This can PROVE that certain cipher combinations are impossible for K4

**Implementation:**
- Use z3-solver Python bindings
- Enumerate cipher family hypotheses (Vigenere+columnar, Bifid+route, etc.)
- For each hypothesis, encode as constraints and check satisfiability
- This is NOT brute force — it's logical deduction

**Estimated effort:** Medium. Z3 API is well-documented. Main work is
encoding each cipher family as constraints.


## ⑤ Deep Learning Cipher Type Identification

**Why it matters:** A 2024 paper (arXiv 2404.02556) demonstrates classification
of 56 different cipher types using CNN + feature engineering. Even with K4's
short length (97 chars), this could provide probabilistic signal about which
cipher family K4 belongs to.

**Approach:**
- Extract statistical features from K4: IC, bigram IC, entropy, max IC at
  various periods, chi-squared vs uniform, chi-squared vs English,
  percentage of repeated bigrams, has-J analysis, etc.
- Run through pre-trained classifier OR train your own on synthetic
  ciphertexts of length ~97
- Get probability distribution over cipher types

**Key resource:** github.com/Nkopal/CipherTypeDetection
  - Handles 50+ cipher types
  - Random Forest + CNN ensemble
  - Open source, Python

**Caution:** 97 characters is short for reliable classification. Train
specifically on length-97 ciphertexts if building custom classifier.

**Estimated effort:** Low-medium. Can use existing tools.


## ⑥ Alternating Optimization for Compound Ciphers (Lasry Method)

**Why it matters:** George Lasry's PhD thesis and subsequent publications
(Cryptologia 2024, Journal of Cryptology 2024) provide a rigorous methodology
for attacking compound ciphers using alternating optimization:

  1. Fix the transposition key, optimize the substitution key
  2. Fix the substitution key, optimize the transposition key
  3. Repeat until convergence

This is directly applicable if K4 uses substitution + transposition layers.

**What's new vs your current approach:**
- Your hybrid pipeline search (Strategy 13) composes two-stage transforms
  but searches each family independently
- Lasry's alternating optimization jointly optimizes BOTH layers
- His nested random restart strategy (Journal of Cryptology 2024) escapes
  local optima better than simple multi-restart

**Implementation:**
- Outer loop: random restart
  - Middle loop: alternate between transposition and substitution
    - Inner loop: hill-climbing / SA on current layer
  - Accept if combined score improves
- Score function: anchor match + n-gram language model
- Known plaintext provides strong initialization signal

**Estimated effort:** Medium. Algorithm is well-described in Lasry's thesis
(available at jku.at). Your existing scoring infrastructure transfers.


## ⑦ Generalized IC and N-gram Fingerprinting

**Why it matters:** The generalized IC (IACR ePrint 2020/1084) extends
Friedman's 1922 IC from single characters to n-grams. For K4:

- Standard IC: 0.0412 (close to random, but not exactly random)
- Compute IC at various assumed periods to detect polyalphabetic structure
- Compute BIGRAM IC, TRIGRAM IC for more discriminating signal
- Compute Kappa test (mutual IC) between K4 and K1/K2/K3 ciphertexts
- These extended statistics may reveal period or relationship signals
  that single-character IC misses

**Also consider:**
- Sliding-window IC profiles (IC computed on overlapping windows)
- IC after hypothetical transposition inversions (if a transposition
  flattened the IC, inverting it should restore English-like IC)
- Chi-squared test against English letter frequencies after each
  candidate transposition

**Estimated effort:** Low. These are statistical tests you can add to your
existing analysis pipeline.


## ⑧ Known-Plaintext Exhaustive Method Elimination

**Why it matters:** Rather than trying to FIND the right method, systematically
ELIMINATE impossible methods. With 19/97 known plaintext characters, many
cipher families can be provably ruled out.

**Approach:**
- For each cipher family (Vigenere, Beaufort, Autokey, Porta, Hill cipher,
  Playfair, Four-square, Bifid, Trifid, ADFGVX, Enigma-like, Gromark, etc.)
  and each plausible key length / key structure:
  - Compute what the key MUST be at the known positions
  - Check internal consistency (e.g., periodic key must repeat)
  - If inconsistent → family is PROVABLY eliminated
- Build a matrix: cipher_family × key_length → possible/impossible
- This narrows the search space before any expensive computation

**What's new:** Your strategies search FOR solutions. This strategy searches
for IMPOSSIBILITY PROOFS. Every family you eliminate is a family you stop
spending GPU time on.

**Estimated effort:** Low-medium. Mostly analytical work with some code.


## ⑨ Gromark Cipher Investigation

**Why it matters:** The Gromark cipher is an obscure but militarily-used
polyalphabetic cipher where the key stream is generated from a running
numerical key that shifts based on previous digits. It's mentioned in
Friedman's military cryptanalysis texts (which Ed Scheidt specifically
referenced as relevant to Kryptos).

- Not in your current strategy set
- Produces flat frequency distribution similar to K4
- Key is a short numeric primer + a running mechanism
- Known plaintext can be used to recover the primer

**Estimated effort:** Low-medium. Algorithm is well-documented.


## ⑩ Transposition-First Hypothesis with Neural Language Scoring

**Why it matters:** Replace n-gram scoring with a small language model
(character-level LSTM or GPT-2 character-level) for scoring candidate
plaintexts. Neural scoring can capture longer-range dependencies than
quadgram statistics.

**Approach:**
- Train a character-level language model on English text
- Use its perplexity as the fitness function in hill-climbing / SA
- The model captures word boundaries, common phrases, and English
  structure that n-gram tables miss
- Particularly valuable when candidates are "almost English" — neural
  scoring provides a smoother gradient toward correct solutions

**Estimated effort:** Medium. Use a pre-trained character-level model.

---

## Priority Ranking

| Priority | Method | Expected Impact | Effort |
|----------|--------|----------------|--------|
| 1 | Z340-style transposition enumeration | High | Medium |
| 2 | Constraint propagation / SAT elimination | High | Medium |
| 3 | Known-plaintext exhaustive elimination | High | Low-Med |
| 4 | Alternating optimization (Lasry) | High | Medium |
| 5 | MCMC key search | Medium-High | Medium |
| 6 | Generalized IC fingerprinting | Medium | Low |
| 7 | Gromark cipher investigation | Medium | Low-Med |
| 8 | ML cipher type identification | Medium | Low-Med |
| 9 | Bayesian cipher analysis | Medium | Med-High |
| 10 | Neural language scoring | Low-Med | Medium |

---

## Key External Resources

- AZDecrypt: Hill-climbing solver that cracked Z340, by Jarl Van Eycke
- George Lasry PhD thesis: jku.at (metaheuristic cryptanalysis methodology)
- Hauer et al. NAACL 2024: aclanthology.org/2024.findings-naacl.147
  (Bayesian classical cipher analysis)
- Cipher Type Detection (56 types): arxiv.org/abs/2404.02556 and
  github.com/Nkopal/CipherTypeDetection
- MCMC for transposition: chance.amstat.org/2020/04/mcmc/
- Generalized IC: eprint.iacr.org/2020/1084
- Z3 SMT solver: github.com/Z3Prover/z3

## Community Status (as of March 2026)

- No new clues from Sanborn since 2020 (NORTHEAST)
- No verified solutions
- Sanborn is ~81; community concern about timeline
- General consensus: K4 uses multiple layers (substitution + transposition)
- Ed Scheidt confirmed methods from Friedman's military cryptanalysis texts
- Active but small community on r/kryptos, kryptosfan.com
