import urllib.request
import re

KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

def build_quagmire_tableau():
    tableau = []
    for i in range(26):
        row = KRYPTOS_ALPHABET[i:] + KRYPTOS_ALPHABET[:i]
        tableau.append(row)
    return tableau

def decrypt_quagmire(ciphertext, key_string, tableau):
    plaintext = ""
    for i, c in enumerate(ciphertext):
        key_char = key_string[i] # no modulo here, key string is presumed long enough
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
        key_char = key_string[i] # no modulo here
        if key_char not in STANDARD_ALPHABET or c not in STANDARD_ALPHABET:
            plaintext += c
            continue
        shift = STANDARD_ALPHABET.index(key_char)
        c_idx = STANDARD_ALPHABET.index(c)
        p_idx = (c_idx - shift) % 26
        plaintext += STANDARD_ALPHABET[p_idx]
    return plaintext

def test_historic_running_key(ciphertext, raw_journal_text, tableau):
    # Clean the journal text: uppercase, remove all non A-Z letters
    clean_text = re.sub(r'[^A-Z]', '', raw_journal_text.upper())
    
    # We need the key material to be at least as long as K4
    if len(clean_text) < len(ciphertext):
        print(f"Error: Provided text is too short. Need at least {len(ciphertext)} chars.")
        return 0
        
    print(f"Testing {len(clean_text) - len(ciphertext) + 1} starting offsets for Howard Carter's Diary...")
    
    matches = 0
    # Test every possible starting offset
    for offset in range(len(clean_text) - len(ciphertext) + 1):
        running_key = clean_text[offset:offset + len(ciphertext)]
        
        # Test Quagmire III
        pt_quag = decrypt_quagmire(ciphertext, running_key, tableau)
        if "EASTNORTHEAST" in pt_quag or "BERLINCLOCK" in pt_quag:
            print(f"MATCH (Quagmire) at Offset {offset}: {pt_quag}")
            matches += 1
            
        # Test Standard Vigenere
        pt_vig = decrypt_vigenere_standard(ciphertext, running_key)
        if "EASTNORTHEAST" in pt_vig or "BERLINCLOCK" in pt_vig:
            print(f"MATCH (Std Vigenere) at Offset {offset}: {pt_vig}")
            matches += 1
            
    return matches

def main():
    tableau = build_quagmire_tableau()
    
    # Text from Howard Carter's diary covering Nov 1 - 27 (1922)
    # Copied from the Griffith Institute historical archives describing the opening of the tomb.
    carters_diary_1922 = """
    Wednesday November 1st.
    To-day I commenced work on the clearance of the rubbish covering the stairway of the tomb of Ramses VI.
    
    Friday November 3rd.
    Workmen's huts cleared completely from the first stair of the tomb of Ramses VI.
    
    Saturday November 4th.
    At about 10am I discovered beneath almost the first hut attacked the first traces of the entrance of the tomb Tutankhamen...
    
    Sunday November 5th.
    Discovered tomb to be intact at least so far as the outer door was concerned.
    
    Sunday November 26th.
    The day of days. Slowly desperately slowly it seemed to us as we watched the remains of passage debris that encumbered the lower part of the doorway were removed. With trembling hands I made a tiny breach in the upper left hand corner. Darkness and blank space, as far as an iron testing-rod could reach, showed that whatever lay beyond was empty, and not filled like the passage we had just cleared. Candle tests were applied as a precaution against possible foul gases, and then, widening the hole a little, I inserted the candle and peered in, Lord Carnarvon, Lady Evelyn and Callender standing anxiously beside me to hear the verdict. At first I could see nothing, the hot air escaping from the chamber causing the candle flame to flicker, but presently, as my eyes grew accustomed to the light, details of the room within emerged slowly from the mist, strange animals, statues, and gold everywhere the glint of gold. For the moment an eternity it must have seemed to the others standing by I was struck dumb with amazement, and when Lord Carnarvon, unable to stand the suspense any longer, inquired anxiously, Can you see anything? it was all I could do to get out the words, Yes, wonderful things.
    """
    
    print("\n--- Running Strategy 9: External Text Key (Carter Diary) ---")
    total_matches = test_historic_running_key(K4, carters_diary_1922, tableau)
    
    if total_matches == 0:
        print("No matches found across all potential offsets of the historic diary.")
        print("The clues `EASTNORTHEAST` and `BERLINCLOCK` did not materialize within the tested text.")

if __name__ == "__main__":
    main()
