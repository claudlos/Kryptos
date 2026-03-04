import itertools

KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

def build_tableau():
    tableau = []
    for i in range(26):
        row = KRYPTOS_ALPHABET[i:] + KRYPTOS_ALPHABET[:i]
        tableau.append(row)
    return tableau

def decrypt_quagmire_char(cipher_char, key_char, tableau):
    if key_char not in KRYPTOS_ALPHABET or cipher_char not in KRYPTOS_ALPHABET:
        return cipher_char
    row_idx = KRYPTOS_ALPHABET.index(key_char)
    row = tableau[row_idx]
    if cipher_char in row:
        col_idx = row.index(cipher_char)
        return KRYPTOS_ALPHABET[col_idx]
    return cipher_char

def decrypt_quagmire_autokey(ciphertext, primer, mode="plain"):
    tableau = build_tableau()
    plaintext = ""
    current_key = list(primer.upper())
    
    for i, c in enumerate(ciphertext):
        if i < len(current_key):
            key_char = current_key[i]
        else:
            key_char = current_key[i]
            
        p_char = decrypt_quagmire_char(c, key_char, tableau)
        plaintext += p_char
        
        if mode == "plain":
            current_key.append(p_char)
        elif mode == "cipher":
            current_key.append(c)
            
    return plaintext

def main():
    primers = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "CIA", "ILLUSION"]
    modes = ["plain", "cipher"]
    
    # Generate all pairs of primers for the two layers (Layer 1 -> Layer 2)
    # We decrypt Layer 2 first, then Layer 1
    pairs = list(itertools.product(primers, repeat=2))
    
    print(f"Testing {len(pairs)} primer combinations for Chained Autokey (Double Quagmire III)...\n")
    
    found = False
    
    for p1, p2 in pairs:
        for mode1 in modes:
            for mode2 in modes:
                # Decrypt the outer layer (L2) to get intermediate ciphertext
                intermediate = decrypt_quagmire_autokey(K4, p2, mode=mode2)
                
                # Decrypt the inner layer (L1) to get final plaintext
                final_pt = decrypt_quagmire_autokey(intermediate, p1, mode=mode1)
                
                if "EASTNORTHEAST" in final_pt or "BERLINCLOCK" in final_pt:
                    print(f"MATCH FOUND!")
                    print(f"Layer 1: Primer '{p1}' ({mode1} autokey)")
                    print(f"Layer 2: Primer '{p2}' ({mode2} autokey)")
                    print(f"Plaintext: {final_pt}")
                    found = True

    if not found:
        print("No matches found for Chained/Multi-Layered Autokey with tested primers.")
        
if __name__ == "__main__":
    main()
