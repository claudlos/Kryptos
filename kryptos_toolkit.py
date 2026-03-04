import argparse
import sys

# Import all strategy scripts
try:
    import strategy1_quagmire
    import strategy2_matrix
    import strategy3_ioc_hillclimb
    import strategy4_autokey
    import strategy5_grilles
    import strategy6_chained_autokey
    import strategy7_segmented
    import strategy8_shifted_running_key
    import strategy9_external_keyer
    import strategy10_fractionation
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def run_all():
    print("="*50)
    print("RUNNING STRATEGY 1: Quagmire Substitution")
    print("="*50)
    strategy1_quagmire.main()
    
    print("\n" + "="*50)
    print("RUNNING STRATEGY 2: Spatial Matrix Masking")
    print("="*50)
    strategy2_matrix.main()
    
    print("\n" + "="*50)
    print("RUNNING STRATEGY 3: IoC Hill Climbing")
    print("="*50)
    strategy3_ioc_hillclimb.main()
    
    print("\n" + "="*50)
    print("RUNNING STRATEGY 4: Autokey Quagmire")
    print("="*50)
    strategy4_autokey.main()
    
    print("\n" + "="*50)
    print("RUNNING STRATEGY 5: Vigenère Grilles")
    print("="*50)
    strategy5_grilles.main()
    
    print("\n" + "="*50)
    print("RUNNING STRATEGY 6: Chained Autokey")
    print("="*50)
    strategy6_chained_autokey.main()
    
    print("\n" + "="*50)
    print("RUNNING STRATEGY 7: Segmented Decryption")
    print("="*50)
    strategy7_segmented.main()

    print("\n" + "="*50)
    print("RUNNING STRATEGY 8: Shifted Running Keys")
    print("="*50)
    strategy8_shifted_running_key.main()

    print("\n" + "="*50)
    print("RUNNING STRATEGY 9: External Text Running Key (Carter Diary)")
    print("="*50)
    strategy9_external_keyer.main()

    print("\n" + "="*50)
    print("RUNNING STRATEGY 10: Fractionated Solvers (Bifid)")
    print("="*50)
    strategy10_fractionation.main()

def main():
    parser = argparse.ArgumentParser(description="Kryptos K4 Cryptanalysis Unified Toolkit")
    parser.add_argument("strategy", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "all"], 
                        help="Strategy number to run (1-10) or 'all' to run all.")
    
    args = parser.parse_args()
    
    strategies = {
        "1": strategy1_quagmire.main,
        "2": strategy2_matrix.main,
        "3": strategy3_ioc_hillclimb.main,
        "4": strategy4_autokey.main,
        "5": strategy5_grilles.main,
        "6": strategy6_chained_autokey.main,
        "7": strategy7_segmented.main,
        "8": strategy8_shifted_running_key.main,
        "9": strategy9_external_keyer.main,
        "10": strategy10_fractionation.main
    }
    
    if args.strategy == "all":
        run_all()
    else:
        print(f"==================================================")
        print(f"RUNNING STRATEGY {args.strategy}")
        print(f"==================================================")
        strategies[args.strategy]()

if __name__ == "__main__":
    main()
