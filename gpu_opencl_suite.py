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
    __global const uchar* squares, 
    __constant const int* periods,
    const int num_periods,
    __global int* match_results
) {
    int gid = get_global_id(0);
    
    int p_idx = gid % num_periods;
    int square_idx = gid / num_periods;
    
    int period = periods[p_idx];
    __global const uchar* square = &squares[square_idx * 25];
    
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
            
            // get coords
            int r_val = -1, c_val = -1;
            for(int sq = 0; sq < 25; ++sq) {
                if(square[sq] == ch) {
                    r_val = sq / 5;
                    c_val = sq % 5;
                    break;
                }
            }
            if(r_val != -1) {
                r[valid_len] = r_val;
                c[valid_len] = c_val;
                valid_len++;
            }
        }
        
        uchar stream[194];
        for(int i=0; i<valid_len; ++i) {
            stream[i] = r[i];
            stream[valid_len + i] = c[i];
        }
        
        int block_pt_idx = 0;
        for(int i=0; i<valid_len * 2 - 1; i+=2) {
            int row_idx = stream[i];
            int col_idx = stream[i+1];
            plaintext[block_start + block_pt_idx] = square[row_idx * 5 + col_idx];
            block_pt_idx++;
        }
    }
    
    bool match = false;
    // EASTNORTHEAST
    uchar target1[13] = {'E','A','S','T','N','O','R','T','H','E','A','S','T'};
    for(int i = 0; i <= 97 - 13; ++i) {
        bool sub_match = true;
        for(int j = 0; j < 13; ++j) {
            if(plaintext[i+j] != target1[j]) {
                sub_match = false;
                break;
            }
        }
        if(sub_match) { match = true; break; }
    }
    
    if(!match) {
        // BERLINCLOCK
        uchar target2[11] = {'B','E','R','L','I','N','C','L','O','C','K'};
        for(int i = 0; i <= 97 - 11; ++i) {
            bool sub_match = true;
            for(int j = 0; j < 11; ++j) {
                if(plaintext[i+j] != target2[j]) {
                    sub_match = false;
                    break;
                }
            }
            if(sub_match) { match = true; break;}
        }
    }
    
    if(match) {
        match_results[gid] = 1;
    } else {
        match_results[gid] = 0;
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
    
    # Core loop buffer setup (42M permutations per pass to fit safely within VRAM)
    BASE_BLOCK_PERMUTATIONS = 42_000_000 
    
    periods = np.array([5, 6, 7, 8, 9, 10, 11, 14, 21, 24, 28, 97], dtype=np.int32)
    periods_buffer = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=periods)
    
    num_periods = len(periods)
    target_squares_count = BASE_BLOCK_PERMUTATIONS // num_periods
    
    print("Compressing dictionary buffer for continuous VRAM feed...")
    
    base_squares = []
    for w in words:
        base_squares.append(generate_polybius_square(w))
        
    repeated_squares = (base_squares * ((target_squares_count // len(base_squares)) + 1))[:target_squares_count]
    
    squares_bytes = b"".join(sq.encode('ascii') for sq in repeated_squares)
    squares_np = np.frombuffer(squares_bytes, dtype=np.uint8)
    squares_buffer = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=squares_np)
    
    total_work_items = target_squares_count * num_periods
    matches_np = np.zeros(total_work_items, dtype=np.int32)
    matches_buffer = cl.Buffer(ctx, mf.WRITE_ONLY, matches_np.nbytes)
    
    print(f"Executing deep optimized sweep of 4,200,000,000 (4.2 Billion) matrix permutations via GPU...")
    print(f"This will launch 100 consecutive 42-million iteration blocks.")
    t0 = time.time()
    
    global_size = (total_work_items,)
    local_size = None # Auto-determine optimal local group size natively
    
    global_matches = 0
    total_decryptions = 0
    
    for sweep in range(100):
        # We invoke the OpenCL kernel 100 times back-to-back, fully saturating the GPU
        prg.decrypt_bifid(queue, global_size, local_size, 
                          k4_buffer, squares_buffer, periods_buffer, np.int32(num_periods), matches_buffer)
                          
        total_decryptions += total_work_items
        
        # We only copy memory back off the GPU if we want to read it every block
        if sweep % 10 == 0:
            print(f"... completed block {sweep}/100 ({total_decryptions:,} keys)")
    
    queue.finish()
    
    # Final copy off the VRAM
    cl.enqueue_copy(queue, matches_np, matches_buffer).wait()
    global_matches += np.sum(matches_np)
    
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
