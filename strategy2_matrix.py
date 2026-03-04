import itertools

# K4 Ciphertext (97 chars) + 1 padding char (?) at the end to make it 98 (7x14)
CIPHERTEXT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR?"
# The target cipher strings for EASTNORTHEAST and BERLINCLOCK
TARGET_EN = "FLRVQQPRNGKSS"
TARGET_BC = "NYPVTTMZFPK"

def create_matrices():
    """Create basic 7x14 and 14x7 matrices."""
    m_7x14 = [list(CIPHERTEXT[i:i+14]) for i in range(0, 98, 14)]
    m_14x7 = [list(CIPHERTEXT[i:i+7]) for i in range(0, 98, 7)]
    return m_7x14, m_14x7

def read_columns(matrix):
    """Read matrix down the columns (from left to right)."""
    cols = len(matrix[0])
    rows = len(matrix)
    result = ""
    for c in range(cols):
        for r in range(rows):
            result += matrix[r][c]
    return result

def read_diagonals(matrix):
    """Read a matrix diagonally."""
    rows = len(matrix)
    cols = len(matrix[0])
    result = ""
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(rows, d + 1)):
            c = d - r
            result += matrix[r][c]
    return result

def check_targets(text, method_name):
    """Check if the transposed text contains the raw ciphertext targets."""
    # We strip the '?' just in case it interferes, though it shouldn't for finding the targets
    text_clean = text.replace("?", "")
    
    found_en = TARGET_EN in text_clean or TARGET_EN[::-1] in text_clean
    found_bc = TARGET_BC in text_clean or TARGET_BC[::-1] in text_clean
    
    if found_en or found_bc:
        print(f"\n[!] MATCH FOUND via {method_name}")
        if found_en:
            print(f"  -> Contains EASTNORTHEAST cipher string '{TARGET_EN}'")
        if found_bc:
            print(f"  -> Contains BERLINCLOCK cipher string '{TARGET_BC}'")
        return True
    return False

def main():
    print(f"Initial Cipertext length (padded): {len(CIPHERTEXT)}")
    m_7x14, m_14x7 = create_matrices()
    
    methods = [
        ("7x14 Read Columns (Left-to-Right)", read_columns(m_7x14)),
        ("7x14 Read Columns (Right-to-Left)", read_columns([row[::-1] for row in m_7x14])),
        ("7x14 Read Diagonals", read_diagonals(m_7x14)),
        ("14x7 Read Columns (Left-to-Right)", read_columns(m_14x7)),
        ("14x7 Read Columns (Right-to-Left)", read_columns([row[::-1] for row in m_14x7])),
        ("14x7 Read Diagonals", read_diagonals(m_14x7)),
    ]
    
    found_any = False
    for name, result_text in methods:
        if check_targets(result_text, name):
            found_any = True
            
    if not found_any:
        print("\nNo direct spatial re-assembly found the 1D target ciphertext strings.")
        print("This implies the targets are either broken across lines (which they are natively),")
        print("or the primary cipher is not *just* a simple 7x14 structural rearrangement.")

if __name__ == "__main__":
    main()
