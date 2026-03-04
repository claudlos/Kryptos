KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONWYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWEREREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINXTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

def build_quagmire_tableau():
    tableau = []
    for i in range(26):
        row = KRYPTOS_ALPHABET[i:] + KRYPTOS_ALPHABET[:i]
        tableau.append(row)
    return tableau

def decrypt_quagmire(ciphertext, key_string, tableau):
    plaintext = ""
    for i, c in enumerate(ciphertext):
        key_char = key_string[i % len(key_string)]
        if key_char not in KRYPTOS_ALPHABET or c not in KRYPTOS_ALPHABET:
            plaintext += c
            continue
        row_idx = KRYPTOS_ALPHABET.index(key_char)
        row = tableau[row_idx]
        if c in row:
            col_idx = row.index(c)
            plaintext += KRYPTOS_ALPHABET[col_idx]
        else:
            plaintext += c
    return plaintext

def decrypt_vigenere_standard(ciphertext, key_string):
    plaintext = ""
    for i, c in enumerate(ciphertext):
        key_char = key_string[i % len(key_string)]
        if key_char not in STANDARD_ALPHABET or c not in STANDARD_ALPHABET:
            plaintext += c
            continue
        shift = STANDARD_ALPHABET.index(key_char)
        c_idx = STANDARD_ALPHABET.index(c)
        p_idx = (c_idx - shift) % 26
        plaintext += STANDARD_ALPHABET[p_idx]
    return plaintext

def test_running_key_offsets(ciphertext, key_material, label, tableau):
    """Tests every possible starting offset of the key material against K4."""
    matches = 0
    k_len = len(key_material)
    
    for offset in range(k_len):
        # Shift the running key by the offset
        dynamic_key = key_material[offset:] + key_material[:offset]
        
        # Test Quagmire III
        pt_quag = decrypt_quagmire(ciphertext, dynamic_key, tableau)
        if "EASTNORTHEAST" in pt_quag or "BERLINCLOCK" in pt_quag:
            print(f"MATCH (Quagmire) - {label} at Offset {offset}: {pt_quag}")
            matches += 1
            
        # Test Standard Vigenere
        pt_vig = decrypt_vigenere_standard(ciphertext, dynamic_key)
        if "EASTNORTHEAST" in pt_vig or "BERLINCLOCK" in pt_vig:
            print(f"MATCH (Std Vigenere) - {label} at Offset {offset}: {pt_vig}")
            matches += 1
            
    return matches

def main():
    tableau = build_quagmire_tableau()
    print("Testing Exhaustive Running Key Offsets...\n")
    
    total_matches = 0
    total_matches += test_running_key_offsets(K4, K1_PT, "K1 Plaintext", tableau)
    total_matches += test_running_key_offsets(K4, K2_PT, "K2 Plaintext", tableau)
    total_matches += test_running_key_offsets(K4, K3_PT, "K3 Plaintext", tableau)
    
    # Let's also test 'KRYPTOS' itself as an infinitely repeating offset.
    # While standard Vigenere solves this, maybe the primer is offset?
    primer = "KRYPTOS"
    total_matches += test_running_key_offsets(K4, primer, "KRYPTOS Primer", tableau)
    
    if total_matches == 0:
        print("No matches found across all potential offsets for K1, K2, or K3 running keys.")
        print("The clues `EASTNORTHEAST` and `BERLINCLOCK` did not materialize.")

if __name__ == "__main__":
    main()
