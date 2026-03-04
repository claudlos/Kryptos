# Kryptos constants
KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ" # The standard Kryptos tableau alphabet

# K4 Ciphertext
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# K1-K3 Plaintexts (simplified, no spaces/punctuation)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONWYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWEREREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINXTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"

def build_tableau():
    """Builds the Quagmire III tableau used in Kryptos."""
    tableau = []
    # In Kryptos, the alphabet is shifted for each row.
    # Actually, K1/K2 used a standard Vigenere tableau but BOTH the row/col headers AND the grid were the KRYPTOS mixed alphabet.
    for i in range(26):
        row = KRYPTOS_ALPHABET[i:] + KRYPTOS_ALPHABET[:i]
        tableau.append(row)
    return tableau

def decrypt_quagmire(ciphertext, key_string):
    """
    Decrypts ciphertext using Quagmire III with KRYPTOS alphabet and the given running key.
    """
    tableau = build_tableau()
    plaintext = ""
    for i, c in enumerate(ciphertext):
        key_char = key_string[i % len(key_string)]
        
        # Find row for key_char
        row_idx = KRYPTOS_ALPHABET.index(key_char)
        row = tableau[row_idx]
        
        # Find ciphertext char in that row
        if c in row:
            col_idx = row.index(c)
            # Plaintext is the column header
            plaintext += KRYPTOS_ALPHABET[col_idx]
        else:
            plaintext += c # fallback for punctuation if any
    return plaintext

def check_clues(text):
    if "EASTNORTHEAST" in text or "BERLINCLOCK" in text:
        return True
    return False

def main():
    print("Testing K1 as running key...")
    k1_test = decrypt_quagmire(K4, K1_PT)
    if check_clues(k1_test): print(f"SUCCESS: {k1_test}")
    
    print("Testing K2 as running key...")
    k2_test = decrypt_quagmire(K4, K2_PT)
    if check_clues(k2_test): print(f"SUCCESS: {k2_test}")
    
    print("Testing K3 as running key...")
    k3_test = decrypt_quagmire(K4, K3_PT)
    if check_clues(k3_test): print(f"SUCCESS: {k3_test}")
    
    # Let's also test them as auto-keys (key starts with PT, then appends the output ciphertext)
    # But for now just the running keys.
    print("\nSnippet of K1 decrypt:")
    print(k1_test[:50])
    print("Snippet of K2 decrypt:")
    print(k2_test[:50])
    print("Snippet of K3 decrypt:")
    print(k3_test[:50])

if __name__ == "__main__":
    main()
