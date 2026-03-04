# Kryptos Deep Research Notes

## Section 1 & 2: Quagmire III (Keyed Vigenère)
The first two sections (K1 and K2) were encrypted using a **Quagmire III** cipher, which is a complex substitution cipher combining a Vigenère Tableau with keyword-mixed alphabets for both the plaintext and ciphertext rows.

- **K1 Keys:** Tableau mixed with `KRYPTOS`, Vigenère keyword is `PALIMPSEST`.
- **K2 Keys:** Tableau mixed with `KRYPTOS`, Vigenère keyword is `ABSCISSA`.
- **Mechanics:** 
  1. An alphabet is written out and scrambled using a keyword (e.g., KRYPTOS then remaining letters: `KRYPTOSABCDEFGH...`).
  2. A Vigenère square is built using this mixed alphabet.
  3. The Vigenère keyword dictates which row of the square is used to substitute the plaintext letter.
- **Vulnerability:** If K4 uses this, solving one of the alphabets simplifies solving the rest. Kasiski examination or Index of Coincidence (IoC) usually finds the key length. However, K4's IoC is *very low* (0.0361), either implying a very long keyword or that Quagmire III was not the sole method used.

## Section 3: Double Columnar Transposition
K3 abandoned substitution entirely for a **Double Columnar Transposition** cipher.

- **Mechanics:** 
  1. The text is written into a grid (matrix) row by row.
  2. The columns are read downwards in a specific permuted order to form an intermediate ciphertext.
  3. This intermediate text is written into a *second* grid of different dimensions and the column-reading process is repeated.
- **Grids Used:** Analysts have discovered various grids that work, such as an initial 21-column row layout, followed by a 28-column layout. Jim Sanborn reportedly used notebooks with 14x24 or 42x8 grid layouts.
- **Implication for K4:** The low IoC of K4 could be explained if K4 was *first* substituted (flattening the frequencies) and *then* transposed (scrambling the n-grams), or if a very complex overlapping transposition matrices were used.

## Panel Layout & K4 Dimensions
- **Physical Sculpture:** 12 feet tall, 20 feet long S-shaped copper screen.
- **Left Side:** The encrypted messages (K1-K4).
- **Right Side:** A Vigenère Tableau.
- **K4 Layout:** K4 is exactly 97 characters long at the bottom of the left panel: `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`. It is a continuous block. Researchers note the letter `W` appears a few times and might act as a segment separator. Analytical approaches often propose matrices like **7x14** (98 slots, accommodating 97 chars + 1 question mark from the end of K3/start of K4) for masking or transposition testing.

## Section 4: Complex Key Generation & Multi-layered Autokeys
Because basic single-layer implementations have failed to crack K4, cryptanalysts hypothesize dynamic key generation models.

1. **Chained Autokey / Autokey-on-Autokey:** The plaintext is first encrypted via Autokey. The *resulting ciphertext* is then re-encrypted by a second Autokey layer. This deeply diffuses statistical frequencies.
2. **Segmented Autokeys:** The cipher could be broken into chunks separated by `W` characters. Each segment resets the autokey primer or changes the Tabula Recta alphabet mixing rules entirely.
## Section 5: Howard Carter's Diaries (External Key Theory)
K3 contains a modified excerpt from November 26, 1922 of Howard Carter's diary ("Slowly, desperately slowly..."). A leading theory is that K4's running key is derived from the *actual, full text* of those expedition journals, which are archived by the Griffith Institute. If K4 uses the diary as a key starting at a random offset, we must ingest the entire transcript, strip punctuation, and test it as an exhaustive running key overlay.

## Section 6: Fractionated Ciphers (Bifid & Playfair)
Because K4's frequencies are completely scrambled (IoC 0.036) but transposition appears unlikely due to the contiguous known plaintext clues (`EASTNORTHEAST`), a polygraphic or fractionated cipher is highly suspected.
- **Playfair:** Substitutes digraphs (letter pairs) using a 5x5 grid. However, K4 has 97 characters (an odd number, incompatible with pure Playfair) and contains double letters (e.g., `BB`, `SS`), which standard Playfair inherently prevents.
- **Bifid:** Converts letters to 5x5 coordinates, separates the row and column numbers, transposes or mixes them, and converts them back to letters. This perfectly flattens frequencies and destroys single-letter statistical properties without visibly rearranging the text macroscopically. Bifid combined with an Autokey or Quagmire layer is a formidable candidate for K4.
