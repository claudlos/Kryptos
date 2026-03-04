import re

# Playfair/Bifid requires a 25 letter alphabet.
# Kryptos text often omits Q or J. We'll merge I/J for standard crypto, but in Kryptos the tableau
# explicitly contains all 26 letters. 
# Wait, a Bifid can be done on a 25-cell grid (5x5). Or a 36-cell grid (6x6) including numbers.
# We will test standard 5x5 Bifid (merging I/J) using Kryptos keywords.

KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

def generate_polybius_square(keyword):
    """Generates a 5x5 Polybius square, merging I and J."""
    keyword = re.sub(r'[^A-Z]', '', keyword.upper()).replace('J', 'I')
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # No J
    
    square_str = ""
    for char in keyword:
        if char not in square_str:
            square_str += char
            
    for char in alphabet:
        if char not in square_str:
            square_str += char
            
    # Convert to 5x5 array
    square = [list(square_str[i:i+5]) for i in range(0, 25, 5)]
    return square

def get_coordinates(char, square):
    if char == 'J': char = 'I'
    if char not in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        return None, None
        
    for r in range(5):
        for c in range(5):
            if square[r][c] == char:
                return r, c
    return None, None

def decrypt_bifid(len_period, ciphertext, square):
    """
    Standard Bifid decryption.
    In Bifid, plaintext is turned into rows/cols. Then rows are printed followed by cols.
    Then paired up and looked back up in the grid.
    To decrypt: Map ciphertext back to coords, split the coordinate stream in half (within the period),
    first half becomes rows, second half becomes columns.
    """
    plaintext = ""
    
    # Process in blocks of 'len_period'
    for block_start in range(0, len(ciphertext), len_period):
        block = ciphertext[block_start:block_start + len_period]
        
        # 1. Convert block to coordinates
        coords = []
        valid_block = ""
        for char in block:
            r, c = get_coordinates(char, square)
            if r is not None:
                coords.extend([r, c])
                valid_block += char
                
        if not valid_block:
            plaintext += block # Punctuation padding or unmapped
            continue
            
        # 2. Split coordinates into rows and cols
        # In ciphertext, the coordinates stream is [R1, R2, R3... C1, C2, C3...]
        n = len(valid_block)
        rows = coords[:n]
        cols = coords[n:]
        
        # 3. Rebuild plaintext
        block_plaintext = ""
        # Handle cases where the coordinates might be truncated (e.g. at end of file, odd number of coords)
        # Standard Bifid relies on exact halving. If it's not perfectly divisible, behavior varies.
        # We'll just zip whatever we have.
        for i in range(min(len(rows), len(cols))):
            r = rows[i]
            c = cols[i]
            block_plaintext += square[r][c]
            
        plaintext += block_plaintext
        
    return plaintext

def main():
    print("--- Running Strategy 10: Bifid Fractionation ---")
    
    keywords = ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLIN", "CLOCK", "SANBORN"]
    periods = [5, 7, 8, 10, 11, 14, 21, 24, 28, 97] # 97 = entire text as one period
    
    total_matches = 0
    
    for kw in keywords:
        square = generate_polybius_square(kw)
        for period in periods:
            decrypted = decrypt_bifid(period, K4, square)
            if "EASTNORTHEAST" in decrypted or "BERLINCLOCK" in decrypted or "EAST" in decrypted:
                print(f"MATCH (Bifid)! Keyword: {kw}, Period: {period}")
                print(f"Result: {decrypted}")
                total_matches += 1
                
    if total_matches == 0:
        print(f"Tested {len(keywords)} keywords across {len(periods)} periods.")
        print("No fractionated patterns (Bifid) yielded the targeted plaintexts.")

if __name__ == "__main__":
    main()
