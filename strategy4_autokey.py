# Kryptos constants
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
    """
    Decrypts using Quagmire III with an autokey.
    mode="plain": Key(i) = Plaintext(i - len(primer)). 
                  The key is [Primer] + [Plaintext]
    mode="cipher": Key(i) = Ciphertext(i - len(primer)).
                  The key is [Primer] + [Ciphertext]
    """
    tableau = build_tableau()
    plaintext = ""
    current_key = list(primer.upper())
    
    for i, c in enumerate(ciphertext):
        if i < len(current_key):
            key_char = current_key[i]
        else:
            # We should have generated enough key by now
            key_char = current_key[i]
            
        p_char = decrypt_quagmire_char(c, key_char, tableau)
        plaintext += p_char
        
        # Extend the key for future letters
        if mode == "plain":
            current_key.append(p_char)
        elif mode == "cipher":
            current_key.append(c)
            
    return plaintext

def main():
    primers = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "EAST", "NORTHEAST",
        "SANBORN", "CIA", "LANGLEY", "ILLUSION", "SHADOWFORCES", "LUCENT", "RQ"
    ]
    
    print(f"Testing {len(primers)} Primers with Plain-Autokey and Cipher-Autokey Quagmire III...\n")
    
    found = False
    for primer in primers:
        # Test Plain Autokey
        pt_plain = decrypt_quagmire_autokey(K4, primer, mode="plain")
        if "EASTNORTHEAST" in pt_plain or "BERLINCLOCK" in pt_plain:
            print(f"MATCH (Plain-Autokey) with primer '{primer}': {pt_plain}")
            found = True
            
        # Test Cipher Autokey
        pt_cipher = decrypt_quagmire_autokey(K4, primer, mode="cipher")
        if "EASTNORTHEAST" in pt_cipher or "BERLINCLOCK" in pt_cipher:
            print(f"MATCH (Cipher-Autokey) with primer '{primer}': {pt_cipher}")
            found = True
            
    if not found:
        print("No matches found for Autokey Quagmire with the tested primers.")
        print("\nSnippet of plaintext with 'KRYPTOS' primer (Plain-Autokey):")
        print(decrypt_quagmire_autokey(K4, "KRYPTOS", mode="plain")[:50])

if __name__ == "__main__":
    main()
