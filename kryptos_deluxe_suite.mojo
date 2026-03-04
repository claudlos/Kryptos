def generate_polybius_square(keyword):
    # Basic string manipulation to avoid regex overhead and ensure Mojo compatibility
    square_str = ""
    for char in keyword:
        if char == 'J': char = 'I'
        if char not in square_str:
            square_str += char
            
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in square_str:
            square_str += char
            
    # Return as a 1D string for faster lookup (instead of 2D array)
    return square_str

def get_coordinates(char, square_str):
    if char == 'J': char = 'I'
    for i in range(25):
        if square_str[i] == char:
            return i // 5, i % 5
    return -1, -1

def decrypt_bifid(len_period, ciphertext, square_str):
    plaintext = ""
    c_len = len(ciphertext)
    
    for block_start in range(0, c_len, len_period):
        end = block_start + len_period
        if end > c_len:
            end = c_len
            
        block = ciphertext[block_start:end]
        
        # 1. Convert block to coordinates
        rows = []
        cols = []
        valid_block = ""
        
        for i in range(len(block)):
            char = block[i]
            r, c = get_coordinates(char, square_str)
            if r != -1:
                rows.append(r)
                cols.append(c)
                valid_block += char
                
        if len(valid_block) == 0:
            plaintext += block
            continue
            
        # 2. In Bifid ciphertext, the stream is [R1, R2... C1, C2...]
        # We need to split the stream and rebuild.
        # Wait, the decryption of Bifid means we take the linear stream of coordinates
        # and pair them back up.
        # stream = [rows[0], rows[1]... rows[n], cols[0], cols[1]... cols[n]]
        stream = rows + cols
        
        # Now pair them: (stream[0], stream[1]), (stream[2], stream[3])...
        block_plaintext = ""
        for i in range(0, len(stream) - 1, 2):
            r = stream[i]
            c = stream[i+1]
            idx = r * 5 + c
            block_plaintext += square_str[idx]
            
        plaintext += block_plaintext
        
    return plaintext

def load_dictionary(filepath):
    words = []
    with open(filepath, "r") as f:
        for line in f:
            words.append(line.strip())
    return words

def main():
    print("==================================================")
    print("Kryptos K4 Deluxe Suite (Mojo Accelerated Sweep)")
    print("==================================================")
    K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    
    words = load_dictionary("k4_dictionary.txt")
    import sys
    
    thread_id = sys.argv[1] if len(sys.argv) > 1 else "MAIN"
    sweep_count = int(sys.argv[2]) if len(sys.argv) > 2 else 92 # 92 * 114120 = ~10.5M
    
    print(f"[{thread_id}] Loaded {len(words)} dictionary words. Testing permutations...")
    
    periods = [5, 6, 7, 8, 9, 10, 11, 14, 21, 24, 28, 97]
    total_decryptions = 0
    matches = 0
    
    print(f"[{thread_id}] Initiating Fractionated Sweep for {sweep_count} iterations...")
    
    for sweep_idx in range(sweep_count):
        for word_idx in range(len(words)):
            keyword = words[word_idx]
            square = generate_polybius_square(keyword)
            
            for p_idx in range(len(periods)):
                period = periods[p_idx]
                decrypted = decrypt_bifid(period, K4, square)
                total_decryptions += 1
                
                if total_decryptions % 2500000 == 0:
                    print(f"[{thread_id}] ...processed {total_decryptions} keys...")
                    
                if "EASTNORTHEAST" in decrypted or "BERLINCLOCK" in decrypted:
                    print(f"[{thread_id}] MATCH FOUND! Keyword:", keyword, "Period:", period)
                    print(decrypted)
                    matches += 1
                
    print(f"\n[{thread_id}] --- Sweep Metrics ---")
    print(f"[{thread_id}] Total Decryptions: {total_decryptions}")
    print(f"[{thread_id}] Total Matches: {matches}")

if __name__ == "__main__":
    main()
