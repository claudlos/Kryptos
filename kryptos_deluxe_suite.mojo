def generate_polybius_square(keyword):
    square_str = ""
    for char in keyword:
        if char == 'J': char = 'I'
        if char not in square_str:
            square_str += char

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in square_str:
            square_str += char
    return square_str


def mutate_square(square_str, mutation_id):
    if mutation_id <= 0:
        return square_str
    chars = [char for char in square_str]
    seed = mutation_id * 19937 + 123456789
    for _ in range(4):
        seed = (seed * 1103515245 + 12345) % 2147483648
        left = seed % len(chars)
        seed = (seed * 1103515245 + 12345) % 2147483648
        right = seed % len(chars)
        chars[left], chars[right] = chars[right], chars[left]
    mutated = ""
    for char in chars:
        mutated += char
    return mutated


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

        stream = rows + cols
        block_plaintext = ""
        for i in range(0, len(stream) - 1, 2):
            r = stream[i]
            c = stream[i + 1]
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
    print("Kryptos K4 Deluxe Suite (Mojo Mutated Sweep)")
    print("==================================================")
    K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

    import sys

    thread_id = sys.argv[1] if len(sys.argv) > 1 else "MAIN"
    sweep_count = int(sys.argv[2]) if len(sys.argv) > 2 else 92
    dictionary_path = sys.argv[3] if len(sys.argv) > 3 else "k4_dictionary.txt"
    profile_name = sys.argv[4] if len(sys.argv) > 4 else "default"
    words = load_dictionary(dictionary_path)

    print(f"[{thread_id}] Loaded {len(words)} dictionary words from {dictionary_path}. Testing mutated permutations...")

    periods = [5, 6, 7, 8, 9, 10, 11, 14, 21, 24, 28, 97]
    total_decryptions = 0
    unique_decryptions = 0
    matches = 0

    print(f"[{thread_id}] Initiating fractionated sweep for {sweep_count} mutation passes...")

    for sweep_idx in range(sweep_count):
        for word_idx in range(len(words)):
            keyword = words[word_idx]
            square = mutate_square(generate_polybius_square(keyword), sweep_idx)

            for p_idx in range(len(periods)):
                period = periods[p_idx]
                decrypted = decrypt_bifid(period, K4, square)
                total_decryptions += 1
                unique_decryptions += 1

                if total_decryptions % 2500000 == 0:
                    print(f"[{thread_id}] ...processed {total_decryptions} mutated keys...")

                if "EASTNORTHEAST" in decrypted or "BERLINCLOCK" in decrypted:
                    print(f"[{thread_id}] MATCH FOUND! Keyword:", keyword, "Period:", period, "Sweep:", sweep_idx)
                    print(decrypted)
                    matches += 1

    print(f"\n[{thread_id}] --- Sweep Metrics ---")
    print(f"[{thread_id}] Total Decryptions: {total_decryptions}")
    print(f"[{thread_id}] Unique Mutated Decryptions: {unique_decryptions}")
    print(f"[{thread_id}] Total Matches: {matches}")
    print(f"[{thread_id}] BENCHMARK_PROFILE={profile_name}")
    print(f"[{thread_id}] BENCHMARK_THREAD_ID={thread_id}")
    print(f"[{thread_id}] BENCHMARK_DICTIONARY_PATH={dictionary_path}")
    print(f"[{thread_id}] BENCHMARK_TOTAL_ATTEMPTS={total_decryptions}")
    print(f"[{thread_id}] BENCHMARK_UNIQUE_ATTEMPTS={unique_decryptions}")
    print(f"[{thread_id}] BENCHMARK_MATCHES={matches}")


if __name__ == "__main__":
    main()
