import sys
import os
import shutil

# Add current directory to path so we can import source
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from source.simulation_engine import SimulationConfig, run_experiment

def get_float(prompt, default=None):
    p = f"{prompt} [{default}]: " if default is not None else f"{prompt}: "
    while True:
        try:
            val = input(p)
            if not val and default is not None:
                return default
            return float(val)
        except ValueError:
            print("Invalid number.")

def get_int(prompt, default=None):
    p = f"{prompt} [{default}]: " if default is not None else f"{prompt}: "
    while True:
        try:
            val = input(p)
            if not val and default is not None:
                return default
            return int(val)
        except ValueError:
            print("Invalid integer.")

def main():
    print("==========================================================")
    print("   PKI/DPKI Simulation Engineering Platform")
    print("==========================================================")
    print("(Values in brackets [] are defaults - press Enter to accept)")
    
    # Defaults
    def_T = 30
    def_V1 = 75.0
    def_V2 = 0.1
    def_p = 0.001
    def_M = 6
    
    print("\nPlease configure base parameters:")
    T = get_float("Period T (s)", def_T)
    V1 = get_float("Risk Cost V1", def_V1)
    V2 = get_float("Update Cost V2", def_V2)
    p = get_float("Attack Rate p (1/s)", def_p)
    M = get_int("Number of Nodes M", def_M)
    
    print("\n----------------------------------------------------------")
    print("Select variable to sweep (multi-group experiment):")
    print("1. T (Period)")
    print("2. V1 (Risk Cost)")
    print("3. V2 (Update Cost)")
    print("4. p (Attack Rate)")
    print("5. M (Number of Nodes)")
    print("(Press Enter to skip multi-group experiment and run single test with current config)")
    
    choice = input("Enter choice (1-5): ")
    
    sweep_var = None
    values = []
    
    if not choice:
        print("\nNo choice made. Running single experiment with current settings.")
        values = [0]
    else:
        if choice == '1': sweep_var = 'T'
        elif choice == '2': sweep_var = 'V1'
        elif choice == '3': sweep_var = 'V2'
        elif choice == '4': sweep_var = 'p'
        elif choice == '5': sweep_var = 'M'
        else:
            print("Invalid choice. Exiting.")
            return

        print(f"\nYou selected to sweep: {sweep_var}")
        vals_str = input(f"Enter values for {sweep_var} (comma separated): ")
        try:
            if sweep_var == 'M':
                values = [int(x.strip()) for x in vals_str.split(',')]
            else:
                values = [float(x.strip()) for x in vals_str.split(',')]
        except ValueError:
            print("Invalid values format.")
            return

    # Clear history records
    base_dir = "platform_verification"
    if os.path.exists(base_dir):
        print(f"\nCleaning up history records in '{base_dir}'...")
        try:
            shutil.rmtree(base_dir)
        except Exception as e:
            print(f"Warning: Failed to clean {base_dir}: {e}")
        
    results = []
    print(f"\nRunning experiments for {len(values)} values...")
    
    for val in values:
        # Create config based on base params + sweep val
        curr_T = val if sweep_var == 'T' else T
        curr_V1 = val if sweep_var == 'V1' else V1
        curr_V2 = val if sweep_var == 'V2' else V2
        curr_p = val if sweep_var == 'p' else p
        curr_M = val if sweep_var == 'M' else M
        
        if sweep_var:
            print(f"Running for {sweep_var}={val} ...")
            suffix = f"{sweep_var}_{val}"
        else:
            print(f"Running single experiment...")
            suffix = "single"
        
        config = SimulationConfig(
            M=curr_M,
            T=curr_T,
            p=curr_p,
            V1=curr_V1,
            V2=curr_V2,
            total_certs=60, # Keep fixed as per previous logic
            total_periods=100 # Keep fixed
        )
        
        res = run_experiment(config, run_id_suffix=suffix)
        results.append(res)
        
    # Display Table
    print("\n==========================================================")
    disp_var = sweep_var if sweep_var else "Experiment"
    print(f" Experiment Results (Varying {disp_var})")
    print("==========================================================")
    
    header = f"{disp_var:<10} | {'Cent. J_Risk':<12} | {'Cent. J_Total':<12} || {'Dist. J_Risk':<12} | {'Dist. J_Total':<12}"
    print(header)
    print("-" * len(header))
    
    for r in results:
        # Get value of sweep var from result dict
        if sweep_var:
            val = r[sweep_var]
            
            # Format val
            if isinstance(val, float):
                val_str = f"{val:.4f}"
                if val > 100: val_str = f"{val:.1f}"
            else:
                val_str = str(val)
        else:
            val_str = "Single"
            
        print(f"{val_str:<10} | {r['C_Risk']:<12.4f} | {r['C_Total']:<12.4f} || {r['D_Risk']:<12.4f} | {r['D_Total']:<12.4f}")
        
    print("==========================================================")

if __name__ == "__main__":
    main()
