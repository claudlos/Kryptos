import itertools

# K4 Ciphertext (padded to 98 to fit exact 7x14 matrix)
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR?"
target_en = "FLRVQQPRNGKSS"
target_bc = "NYPVTTMZFPK"

def get_grid(text, rows, cols):
    return [list(text[i:i+cols]) for i in range(0, rows*cols, cols)]

def generate_masks(rows, cols):
    """
    Generates logical grille masks.
    A true grille involves holes. If we slide a mask over 98 characters and read out
    the letters underneath the holes, we get a new string.
    There are an astronomical number of grilles. For this script we will try:
    1. A mask of every Nth letter (e.g. 2, 3, 4, 5, 7)
    2. Reading specific matrix blocks (top half, left half, every other column)
    """
    masks = []
    
    # Simple modulus masks
    for n in range(2, 8):
        masks.append({
            "name": f"Every {n}th character",
            "indices": [i for i in range(rows * cols) if i % n == 0]
        })
        
    # Column specific masks
    for start_col in range(4):
        # Taking every 2nd or 3rd column
        indices = []
        for r in range(rows):
            for c in range(start_col, cols, 2): # stride of 2
                indices.append(r * cols + c)
        masks.append({"name": f"Every 2nd column starting at {start_col}", "indices": indices})
        
    return masks

def apply_mask(text, indices):
    return "".join([text[i] for i in indices if i < len(text)])

def main():
    print(f"Total Characters: {len(K4)}")
    masks = generate_masks(7, 14)
    print(f"Testing {len(masks)} geometric/mathematical masks on the K4 matrix...")
    
    found = False
    for mask in masks:
        masked_text = apply_mask(K4, mask["indices"])
        if target_en in masked_text or target_bc in masked_text:
            print(f"MATCH FOUND with mask: {mask['name']}")
            print(f"Result length: {len(masked_text)} - {masked_text}")
            found = True
            
    if not found:
        print("\nNo continuous clue strings found under the tested mask geometries.")
        # Print an example of one mask output
        example = apply_mask(K4, masks[0]["indices"])
        print(f"Example output ({masks[0]['name']}): {example}")

if __name__ == "__main__":
    main()
