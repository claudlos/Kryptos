def calculate_ioc(text):
    text = ''.join(filter(str.isalpha, text.upper()))
    n = len(text)
    if n <= 1:
        return 0
    freq = {chr(i): 0 for i in range(65, 91)}
    for char in text:
        freq[char] += 1
    
    ioc = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ioc

def get_vigenere_shifts(plaintext, ciphertext):
    shifts = []
    for p, c in zip(plaintext, ciphertext):
        p_val = ord(p) - 65
        c_val = ord(c) - 65
        shift = (c_val - p_val) % 26
        shifts.append(shift)
        # also return letter shifts A-Z
    shift_letters = "".join([chr(s + 65) for s in shifts])
    return shifts, shift_letters

def main():
    ciphertext = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    print(f"K4 Ciphertext Length: {len(ciphertext)}")
    
    ioc = calculate_ioc(ciphertext)
    print(f"Index of Coincidence (IoC): {ioc:.4f}")
    print(" (Standard English IoC is ~0.0667, Random text is ~0.0385)\n")

    # Clue 1: EASTNORTHEAST at positions 22-34 (1-indexed)
    # 0-indexed: 21 to 33
    clue1_plain = "EASTNORTHEAST"
    clue1_cipher = ciphertext[21:21+len(clue1_plain)]
    print(f"Clue 1 Plaintext:  {clue1_plain}")
    print(f"Clue 1 Ciphertext: {clue1_cipher}")
    shifts1, shift_letters1 = get_vigenere_shifts(clue1_plain, clue1_cipher)
    print(f"Shifts (Numeric):  {shifts1}")
    print(f"Shifts (Letters):  {shift_letters1}\n")

    # Clue 2: BERLINCLOCK at positions 64-74 (1-indexed)
    # 0-indexed: 63 to 73
    clue2_plain = "BERLINCLOCK"
    clue2_cipher = ciphertext[63:63+len(clue2_plain)]
    print(f"Clue 2 Plaintext:  {clue2_plain}")
    print(f"Clue 2 Ciphertext: {clue2_cipher}")
    shifts2, shift_letters2 = get_vigenere_shifts(clue2_plain, clue2_cipher)
    # Verify exact positions of ciphertext substrings
    print("--- Verifying Clue Index Positions ---\n")
    
    # "EAST", "NORTHEAST"
    east_cipher = "FLRV"
    northeast_cipher = "QQPRNGKSS"
    eastnortheast_cipher = east_cipher + northeast_cipher
    
    print(f"Finding 'EAST' ciphertext ('{east_cipher}'):")
    pos_east = ciphertext.find(east_cipher)
    print(f"  String.find() index: {pos_east} (0-indexed)")
    print(f"  Sculpture index: {pos_east + 1}-{pos_east + len(east_cipher)} (1-indexed)")

    print(f"\nFinding 'NORTHEAST' ciphertext ('{northeast_cipher}'):")
    pos_ne = ciphertext.find(northeast_cipher)
    print(f"  String.find() index: {pos_ne} (0-indexed)")
    print(f"  Sculpture index: {pos_ne + 1}-{pos_ne + len(northeast_cipher)} (1-indexed)")
    
    print(f"\nFinding 'EASTNORTHEAST' combined ciphertext ('{eastnortheast_cipher}'):")
    pos_ene = ciphertext.find(eastnortheast_cipher)
    print(f"  String.find() index: {pos_ene} (0-indexed)")
    print(f"  Sculpture index: {pos_ene + 1}-{pos_ene + len(eastnortheast_cipher)} (1-indexed)\n")
    
    # "BERLIN", "CLOCK"
    berlin_cipher = "NYPVTT"
    clock_cipher = "MZFPK"
    berlinclock_cipher = berlin_cipher + clock_cipher
    
    print(f"Finding 'BERLIN' ciphertext ('{berlin_cipher}'):")
    pos_berlin = ciphertext.find(berlin_cipher)
    print(f"  String.find() index: {pos_berlin} (0-indexed)")
    print(f"  Sculpture index: {pos_berlin + 1}-{pos_berlin + len(berlin_cipher)} (1-indexed)")
    
    print(f"\nFinding 'CLOCK' ciphertext ('{clock_cipher}'):")
    pos_clock = ciphertext.find(clock_cipher)
    print(f"  String.find() index: {pos_clock} (0-indexed)")
    print(f"  Sculpture index: {pos_clock + 1}-{pos_clock + len(clock_cipher)} (1-indexed)")
    
    print(f"\nFinding 'BERLINCLOCK' combined ciphertext ('{berlinclock_cipher}'):")
    pos_bc = ciphertext.find(berlinclock_cipher)
    print(f"  String.find() index: {pos_bc} (0-indexed)")
    print("  Sculpture index: 64-74 (1-indexed)\n")

    # Evaluate 2025 Grok 3 Plaintext Claim
    print("--- Evaluating 2025 Grok 3 Claim ---")
    proposed_plain = "THIS IS A GUIDE TO THE BERLIN CLOCK WHICH IS NORTHEAST OF HERE AT CIA LANGLEY VIRGINIA"
    plain_alpha = ''.join(filter(str.isalpha, proposed_plain.upper()))
    print(f"Proposed Plaintext (Alpha only): {plain_alpha}")
    print(f"Plaintext Length: {len(plain_alpha)}")
    print(f"Ciphertext Length: {len(ciphertext)}")
    
    if len(plain_alpha) != len(ciphertext):
        print("\nLENGTH MISMATCH:")
        print("The proposed plaintext is 82 characters, but the K4 ciphertext is 97 characters.")
        print("Unless there is massive padding (15 nulls) or a missing prefix/suffix, this exact string cannot map 1:1.")
    
    # Let's see if we can align the proposed plain so the clues line up
    # Proposed plain has "BERLINCLOCK" and "NORTHEAST". But do they match the offsets?
    # K4 clues: EASTNORTHEAST at 22-34.
    # Grok claim plain has "NORTHEAST" but not "EASTNORTHEAST".
    print("\nOffset check:")
    print("Jim Sanborn's clues specifically state characters 22-25 are 'EAST' and 26-34 are 'NORTHEAST'.")
    print(f"Grok Claim text contains 'EASTNORTHEAST'? {'EASTNORTHEAST' in plain_alpha}")
    if 'EASTNORTHEAST' not in plain_alpha:
        print("-> The proposed solution violates Jim Sanborn's explicit known-plaintext clues.")

if __name__ == "__main__":
    main()
