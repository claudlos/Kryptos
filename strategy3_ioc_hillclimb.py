import random
import math

CIPHERTEXT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

def calculate_ioc(text):
    n = len(text)
    if n <= 1: return 0
    freq = {chr(i): 0 for i in range(65, 91)}
    for char in text:
        freq[char] += 1
    ioc = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    return ioc

def apply_columnar_transposition(text, col_order):
    """
    Applies a columnar transposition given a column order.
    Example: col_order = [2, 0, 1] means read column 2, then column 0, then column 1.
    """
    width = len(col_order)
    # Pad text to a multiple of width for easier grid math
    padded_len = math.ceil(len(text) / width) * width
    padded_text = text.ljust(padded_len, 'X')
    
    # Build grid
    grid = [padded_text[i:i+width] for i in range(0, padded_len, width)]
    
    result = ""
    # Transpose by reading down the requested columns
    for col_idx in col_order:
        for row in grid:
            result += row[col_idx]
            
    # Strip padding if we care about exact IoC, but IoC works fine on padded as long as it's small.
    # For now, evaluate IoC on the transposed text straight
    return result

def fitness(text):
    """
    Since overall IoC is invariant under transposition,
    we use the known ciphertext strings as our fitness targets.
    We reward the presence of bigrams, trigrams, and full strings from the targets.
    """
    TARGETS = ["FLRVQQPRNGKSS", "NYPVTTMZFPK"]
    score = 0
    for target in TARGETS:
        # Reward full target
        if target in text:
            score += 1000000
        # Reward trigrams
        for i in range(len(target) - 2):
            if target[i:i+3] in text:
                score += 100
        # Reward bigrams
        for i in range(len(target) - 1):
            if target[i:i+2] in text:
                score += 5
    return score

def hill_climb_transposition(width, iterations=10000):
    best_order = list(range(width))
    best_text = apply_columnar_transposition(CIPHERTEXT, best_order)
    best_score = fitness(best_text)
    
    # We'll do multiple random restarts since hill climbing gets stuck in local optima
    restarts = 5
    overall_best_order = best_order
    overall_best_score = best_score
    overall_best_text = best_text
    
    for _ in range(restarts):
        current_order = list(range(width))
        random.shuffle(current_order)
        current_text = apply_columnar_transposition(CIPHERTEXT, current_order)
        current_score = fitness(current_text)
        
        for _ in range(iterations):
            new_order = current_order.copy()
            # Mutate: swap two random columns
            idx1, idx2 = random.sample(range(width), 2)
            new_order[idx1], new_order[idx2] = new_order[idx2], new_order[idx1]
            
            new_text = apply_columnar_transposition(CIPHERTEXT, new_order)
            new_score = fitness(new_text)
            
            if new_score > current_score:
                current_score = new_score
                current_order = new_order
                current_text = new_text
                
        if current_score > overall_best_score:
            overall_best_score = current_score
            overall_best_order = current_order
            overall_best_text = current_text
            
    return overall_best_order, overall_best_score, overall_best_text

def main():
    print(f"Original cipher fitness: {fitness(CIPHERTEXT)}\n")
    
    # Test common K3/Kryptos grid widths
    test_widths = [7, 8, 14, 21, 24, 28]
    
    for w in test_widths:
        print(f"--- Running Hill Climbing for Width {w} ---")
        best_order, best_score, best_text = hill_climb_transposition(w, iterations=5000)
        print(f"Best Score: {best_score}")
        print(f"Best Order: {best_order}")
        if best_score > 500: # Arbitrary threshold for a "good" partial reassembly
            print(f"Reassembled Text snippet: {best_text[:50]}...\n")
        else:
            print("No significant reassembly found.\n")

if __name__ == "__main__":
    main()
