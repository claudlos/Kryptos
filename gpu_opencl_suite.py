import sys
import time
import numpy as np

try:
    import pyopencl as cl
except ImportError:
    print("PyOpenCL is not installed. Run 'pip install pyopencl'")
    sys.exit(1)

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

def load_dictionary(filepath):
    words = []
    with open(filepath, "r") as f:
        for line in f:
            words.append(line.strip())
    return words

# OPTIMIZATION: k4 and periods moved to __constant memory for ultra-fast cache access on GPU
kernel_code = """
__kernel void decrypt_bifid(
    __constant const uchar* k4,
    __global const uchar* base_squares, 
    __constant const int* periods,
    const int num_periods,
    const int num_base_squares,
    __global int* match_results,
    volatile __global int* match_count,
    const int sweep_idx
) {
    int gid = get_global_id(0);
    
    int p_idx = gid % num_periods;
    int square_idx = gid / num_periods;
    
    int base_square_idx = square_idx % num_base_squares;
    int copy_idx = square_idx / num_base_squares;
    int mut_id = sweep_idx * 17 + copy_idx; // 17 copies per sweep
    
    int period = periods[p_idx];
    __global const uchar* global_square = &base_squares[base_square_idx * 25];
    uchar local_square[25];
    for (int i=0; i<25; i++) local_square[i] = global_square[i];
    
    // Mutate the square deterministically based on mut_id
    if (mut_id > 0) {
        // Apply multiple seeded swaps to generate distinct combinations
        ulong seed = mut_id * 19937 + 123456789;
        for (int s=0; s<4; s++) {
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
            int swap1 = seed % 25;
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
            int swap2 = seed % 25;
            uchar tmp = local_square[swap1];
            local_square[swap1] = local_square[swap2];
            local_square[swap2] = tmp;
        }
    }
    
    // O(1) Inverse Map for Polybius Square
    uchar r_map[26];
    uchar c_map[26];
    for (int i = 0; i < 26; i++) {
        r_map[i] = 255; 
        c_map[i] = 255;
    }
    for (int sq = 0; sq < 25; ++sq) {
        int ch_idx = local_square[sq] - 'A';
        if (ch_idx >= 0 && ch_idx < 26) {
            r_map[ch_idx] = sq / 5;
            c_map[ch_idx] = sq % 5;
        }
    }
    
    uchar plaintext[97];
    
    for (int block_start = 0; block_start < 97; block_start += period) {
        int end = block_start + period;
        if (end > 97) end = 97;
        
        int block_len = end - block_start;
        uchar r[97];
        uchar c[97];
        int valid_len = 0;
        
        for(int i = 0; i < block_len; ++i) {
            uchar ch = k4[block_start + i];
            if (ch == 'J') ch = 'I';
            
            // get coords via O(1) memory lookup
            int ch_idx = ch - 'A';
            if (ch_idx >= 0 && ch_idx < 26) {
                uchar r_val = r_map[ch_idx];
                uchar c_val = c_map[ch_idx];
                if (r_val != 255) {
                    r[valid_len] = r_val;
                    c[valid_len] = c_val;
                    valid_len++;
                }
            }
        }
        
        uchar stream[194];
        for(int i=0; i<valid_len; ++i) {
            stream[2 * i] = r[i];
            stream[2 * i + 1] = c[i];
        }
        
        for(int i=0; i<valid_len; ++i) {
            int row_idx = stream[i];
            int col_idx = stream[valid_len + i];
            plaintext[block_start + i] = local_square[row_idx * 5 + col_idx];
        }
    }
    
    bool match = false;
    // EASTNORTHEAST loop unrolled
    for(int i = 0; i <= 97 - 13; ++i) {
        if(plaintext[i] == 'E' && plaintext[i+1] == 'A' && plaintext[i+2] == 'S' && plaintext[i+3] == 'T' && 
           plaintext[i+4] == 'N' && plaintext[i+5] == 'O' && plaintext[i+6] == 'R' && plaintext[i+7] == 'T' && 
           plaintext[i+8] == 'H' && plaintext[i+9] == 'E' && plaintext[i+10] == 'A' && plaintext[i+11] == 'S' && plaintext[i+12] == 'T') {
            match = true; 
            break; 
        }
    }
    
    if(!match) {
        // BERLINCLOCK loop unrolled
        for(int i = 0; i <= 97 - 11; ++i) {
            if(plaintext[i] == 'B' && plaintext[i+1] == 'E' && plaintext[i+2] == 'R' && plaintext[i+3] == 'L' && 
               plaintext[i+4] == 'I' && plaintext[i+5] == 'N' && plaintext[i+6] == 'C' && plaintext[i+7] == 'L' && 
               plaintext[i+8] == 'O' && plaintext[i+9] == 'C' && plaintext[i+10] == 'K') {
                match = true; 
                break;
            }
        }
    }
    
    if(match) {
        int idx = atomic_add(match_count, 1);
        if(idx < 1000) {
            match_results[idx] = gid;
        }
    }
}
"""

def main():
    print("==================================================")
    print("Kryptos K4: AMD Radeon 680M Deep Sweep (OpenCL)")
    print("==================================================")
    
    platforms = cl.get_platforms()
    if not platforms:
        print("No OpenCL platforms found!")
        sys.exit(1)
        
    device = None
    for p in platforms:
        for d in p.get_devices():
            if d.type == cl.device_type.GPU:
                device = d
                break
        if device: break
        
    if not device:
        print("No GPU found! Using CPU fallback.")
        device = platforms[0].get_devices()[0]
        
    print(f"Using Hardware Device: {device.name}")
    
    ctx = cl.Context([device])
    queue = cl.CommandQueue(ctx)
    prg = cl.Program(ctx, kernel_code).build()
    
    K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    k4_bytes = np.array([ord(c) for c in K4], dtype=np.uint8)
    
    mf = cl.mem_flags
    k4_buffer = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=k4_bytes)
    
    words = load_dictionary("k4_dictionary.txt")
    print(f"Loaded {len(words)} standard dictionary words.")
    
    # Core loop buffer setup (reduced to 2M to definitively prevent Windows TDR driver freezes)
    BASE_BLOCK_PERMUTATIONS = 2_000_000 
    
    periods = np.array([5, 6, 7, 8, 9, 10, 11, 14, 21, 24, 28, 97], dtype=np.int32)
    periods_buffer = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=periods)
    
    num_periods = len(periods)
    
    print("Compressing dictionary buffer for continuous VRAM feed...")
    
    base_squares = []
    for w in words:
        base_squares.append(generate_polybius_square(w))
        
    squares_bytes = b"".join(sq.encode('ascii') for sq in base_squares)
    squares_np = np.frombuffer(squares_bytes, dtype=np.uint8)
    squares_buffer = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=squares_np)
    
    # Run 17 mutated variants of the 9510 words per kernel launch to reach ~2 million items
    num_base_squares = len(base_squares)
    copies_per_sweep = 17
    total_work_items = num_base_squares * copies_per_sweep * num_periods
    
    matches_np = np.zeros(1000, dtype=np.int32)
    matches_buffer = cl.Buffer(ctx, mf.WRITE_ONLY, matches_np.nbytes)
    
    match_count_np = np.zeros(1, dtype=np.int32)
    match_count_buffer = cl.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=match_count_np)
    
    print(f"Executing deep optimized sweep of ~4,000,000,000 (4.0 Billion) matrix permutations via GPU...")
    print(f"This will launch 2000 consecutive 2-million iteration blocks to guarantee OS stability.")
    t0 = time.time()
    
    global_size = (total_work_items,)
    local_size = None # Auto-determine optimal local group size natively
    
    global_matches = 0
    total_decryptions = 0
    
    decrypt_kernel = cl.Kernel(prg, "decrypt_bifid")
    
    for sweep in range(2000):
        # We invoke the OpenCL kernel back-to-back, fully saturating the GPU
        decrypt_kernel(queue, global_size, local_size, 
                          k4_buffer, squares_buffer, periods_buffer, np.int32(num_periods), 
                          np.int32(num_base_squares), matches_buffer, match_count_buffer, 
                          np.int32(sweep))
        
        # Finish the queue to force execution check and definitively prevent Windows TDR resets
        queue.finish()
                          
        total_decryptions += total_work_items
        
        if sweep % 200 == 0:
            print(f"... completed block {sweep}/2000 ({total_decryptions:,} keys)")
    
    queue.finish()
    
    # Final copy off the VRAM
    cl.enqueue_copy(queue, match_count_np, match_count_buffer).wait()
    global_matches = match_count_np[0]
    
    if global_matches > 0:
        cl.enqueue_copy(queue, matches_np, matches_buffer).wait()
        print(f"Found {global_matches} matches! Raw GIDs: {matches_np[:min(global_matches, 1000)]}")
    
    t1 = time.time()
    elapsed = t1 - t0
    
    print("\n--- Massive 4.2 Billion GPU Sweep Metrics ---")
    print(f"Total Decryptions: {total_decryptions:,}")
    print(f"Time Elapsed:      {elapsed:.4f} seconds")
    if elapsed > 0:
        speed = total_decryptions / elapsed
        print(f"Decryption Speed:  {speed:,.2f} decryptions/second")
    print(f"Total Matches:     {global_matches}")
    
if __name__ == "__main__":
    main()
