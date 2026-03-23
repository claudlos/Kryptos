# Kryptos K4 Solving Plans

Based on the intelligence gathered, the objective is to crack the 97-character K4 ciphertext or cryptanalytically verify recent claims of its solution. The known ciphertext and the confirmed plaintext clues offer a solid Known-Plaintext Attack (KPA) foundation.

## The Data
**Ciphertext (97 chars):**
`OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`

**Known Plaintext Mappings:**
- Pos 22-34: `EASTNORTHEAST`
- Pos 64-74: `BERLINCLOCK`

## Plan A: Evaluating the 2025 Naughton Claim
**Objective:** Determine the cryptographic method used if the plaintext is indeed the claimed 2025 solution.
**Proposed Plaintext Claim:**
`THIS IS A GUIDE TO THE BERLIN CLOCK WHICH IS NORTHEAST OF HERE AT CIA LANGLEY, VIRGINIA`
*Note: This plaintext is 83 characters long (excluding spaces), but the ciphertext is 97 characters. The plan must account for a possible 14-character discrepancy (e.g., padding, nulls, or a longer variant of the phrase).*
**Methodology:**
1. Align the proposed plaintext with the ciphertext using the known anchors (`EASTNORTHEAST` and `BERLINCLOCK`).
2. Run differential cryptanalysis to see if a Vigenère, Quagmire, or Beaufort variant links the plain and cipher characters.
3. If an algorithmic link is found, deduce the keyword or key matrix.

## Plan B: Classic Known-Plaintext Attack (KPA)
**Objective:** Use the exact positional knowledge of the clues to deduce the overarching cipher technique. 
**Methodology:**
1. Given that K1 and K2 used variants of the Vigenère cipher (specifically Quagmire III) and K3 used a transposition cipher, K4 might use a deeper polyalphabetic or spatial cipher.
2. Calculate the Index of Coincidence (IoC) of the K4 ciphertext to determine if it is purely polyalphabetic or if there's a transposition element.
3. Brute-force key lengths (e.g., up to length 15) against the specific known plain-cipher pairings:
   - Plain: `EASTNORTHEAST` -> Cipher: `MZLDKRNSHGNFI` (Adjusting positions based on actual string matches in K4).
   - Plain: `BERLINCLOCK` -> Cipher: `FLRLSRNFELG` (Adjusting positions appropriately).
4. Utilize an automated hill-climbing algorithm over standard classical cipher types (Playfair, Four-Square, Bifid) using the known plaintext as the fitness function anchor.

## Plan C: Masking and Matrix Transposition
**Objective:** Leverage the physical spatial arrangement of the Kryptos sculpture itself.
**Methodology:**
1. Map the 97 K4 characters into a 2D matrix matching the sculpture's panel dimensions.
2. Apply matrices from K1, K2, or K3 as a cut-out "mask" (grille) over the K4 grid.
3. Test vertical, horizontal, and diagonal read-outs of the masked letters to locate the strings `BERLINCLOCK` and `EASTNORTHEAST`.

## Next Steps for Execution
1. Script a Python analysis tool to compute the IoC and test basic Vigenère/Quagmire derivations for the known plaintext-ciphertext offsets.
2. Verify the exact index positions of the clues within the 97-character string.
3. Determine if the 2025 plaintext claim can mathematically generate the K4 ciphertext under any standard encryption scheme.

## Initial Analysis Findings (March 2026)
- The K4 ciphertext is precisely 97 characters.
- The **Index of Coincidence (IoC)** is `0.0361`. Standard English is `~0.0667` and perfectly random text is `~0.0385`. An IoC lower than random suggests either a highly polyalphabetic cipher (long key) or a multi-layer encryption strategy (e.g. substitution followed by transposition) that totally flattens character frequencies.
- Basic Vigenère shifts for the known clues do not yield a legible repeating keyword.
  - `EASTNORTHEAST` -> `FLRVQQPRNGKSS` yields shifts: `BLZCDCYYGCKAZ`
  - `BERLINCLOCK` -> `NYPVTTMZFPK` yields shifts: `MUYKLGKORNA`

### Evaluation of the 2025 Grok 3 Claim
The proposed AI plaintext is: `"THIS IS A GUIDE TO THE BERLIN CLOCK WHICH IS NORTHEAST OF HERE AT CIA LANGLEY VIRGINIA"`
- **Mathematical Impossibility (Length):** The plaintext contains 82 alphabetic characters. The ciphertext contains 97. An exact 1:1 encryption (substitution, transposition, Vigenere, etc.) is not possible without significant null padding.
- **Contradiction of Official Clues:** Sanborn verified that indices 22-34 map exactly to `EASTNORTHEAST`. The Grok 3 plaintext contains `NORTHEAST` but entirely omits the preceding `EAST`. 
- **Conclusion:** The AI-generated string is definitively an hallucination or a very rough thematic guess, not a cryptanalytically sound decryption of the K4 ciphertext.
