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

def decrypt_quagmire_running(ciphertext, keyword):
    """Standard Vigenere/Quagmire string decryption."""
    tableau = build_tableau()
    plaintext = ""
    for i, c in enumerate(ciphertext):
        k = keyword[i % len(keyword)]
        plaintext += decrypt_quagmire_char(c, k, tableau)
    return plaintext

def decrypt_quagmire_autokey(ciphertext, primer, mode="plain"):
    tableau = build_tableau()
    plaintext = ""
    current_key = list(primer.upper())
    for i, c in enumerate(ciphertext):
        key_char = current_key[i] if i < len(current_key) else current_key[i]
        p_char = decrypt_quagmire_char(c, key_char, tableau)
        plaintext += p_char
        if mode == "plain": current_key.append(p_char)
        elif mode == "cipher": current_key.append(c)
    return plaintext

def main():
    # Split K4 by the character 'W'
    # Important: 'W' exists in K4 at indices 20, 36, 45, 59, 74
    # OBKRUOXOGHULBSOLIFBB [W] FLRVQQPRNGKSSOT [W] TQSJQSSEKZZ [W] ATJKLUDIA [W] INFBNYPVTTMZFPK [W] GDKZXTJCDIGKUHUAUEKCAR
    
    segments = K4.split('W')
    print(f"K4 Split by 'W' results in {len(segments)} segments:\n")
    for i, seg in enumerate(segments):
        print(f"Segment {i+1} ({len(seg)} chars): {seg}")
        
    print("\nTesting Segmented Decryption (Resetting Cipher per Segment)...")
    
    keywords = ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLIN", "CLOCK", "EAST"]
    
    found = False
    
    for kw in keywords:
        # Test 1: Standard Quagmire III per segment (Keyword restarts at beginning of each segment)
        pt_standard = []
        for seg in segments:
            pt_standard.append(decrypt_quagmire_running(seg, kw))
        full_pt_std = "W".join(pt_standard) # Rejoin them with W to easily search
        
        if "EASTNORTHEAST" in full_pt_std or "BERLINCLOCK" in full_pt_std:
            print(f"MATCH (Segmented Standard) with keyword '{kw}':\n{full_pt_std}\n")
            found = True
            
        # Test 2: Autokey per segment (Primer restarts at beginning of each segment)
        pt_auto_plain = []
        for seg in segments:
            pt_auto_plain.append(decrypt_quagmire_autokey(seg, kw, mode="plain"))
        full_pt_auto = "W".join(pt_auto_plain)
        
        if "EASTNORTHEAST" in full_pt_auto or "BERLINCLOCK" in full_pt_auto:
            print(f"MATCH (Segmented Plain-Autokey) with primer '{kw}':\n{full_pt_auto}\n")
            found = True

    if not found:
        print("No matches found for Segmented Decryption with tested keywords.")

if __name__ == "__main__":
    main()
