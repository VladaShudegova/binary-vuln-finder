import angr
import logging
import os
import sys

# add the project root to sys.path to import your modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from efficient.static_analysis import MPCPlanner

def run_integration_test():
    """
    Integration test for MPCPlanner. 
    It identifies dangerous library calls (targets) and builds a static plan.
    """

    binary_path = "../elf_files/test_mpc_1_x86"
    
    if not os.path.exists(binary_path):
        print(f"[-] Binary not found at {binary_path}")
        return

    # initialize angr project
    # auto_load_libs=False is crucial to keep the CFG focused on the main binary
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # automatic target discovery via PLT (Procedure Linkage Table)
    danger_functions = ["strcpy", "strcat", "gets", "memcpy", "memmove"]
    targets = []
    
    for func_name in danger_functions:
        if func_name in project.loader.main_object.plt:
            plt_addr = project.loader.main_object.plt[func_name]
            targets.append((func_name, plt_addr))

    if not targets:
        print("[-] No dangerous functions found in PLT. Check your compilation flags (-no-pie).")
        return

    # initialize the Planner
    # this will trigger the CFG generation and DiGraph construction
    planner = MPCPlanner(project)
    
    # get the entry point (main) address
    main_symbol = project.loader.find_symbol('main')
    if not main_symbol:
        print("[-] 'main' symbol not found. Is the binary stripped?")
        return
    
    main_addr = main_symbol.rebased_addr
    print(f"[*] Analysis started from main at {hex(main_addr)}")

    # analyze each target
    for name, addr in targets:
        print(f"\n[!] Target identified: {name} at {hex(addr)}")
        
        # calculate the plan using our Reachability + Dominators logic
        results = planner.find_all_paths(main_addr, addr)
        

        print(f"    - Corridor size:  {len(results['corridor'])} blocks")
        print(f"    - Milestones:     {len(results['milestones'])} blocks")
        print(f"    - Uncertain:      {len(results['uncertain'])} blocks (indirect jumps)")

        if results['corridor']:
            print(f"    [+] SUCCESS: Static path to {name} is mapped.")
        else:
            print(f"    [-] WARNING: {name} is unreachable in static CFG. DSE might be needed.")

if __name__ == "__main__":
    run_integration_test()
