import angr
import claripy
import logging
import os
import sys


# add the project root to sys.path to import your modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from efficient.dynamic_analysis import DirectedSearch
from efficient.static_analysis import MPCPlanner
from efficient.scanner import VulnerabilityScanner


binary_path = "./elf_files/test_mpc_1_x86"
    
if not os.path.exists(binary_path):
    print(f"[-] Binary not found at {binary_path}")

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
    

# static Analysis Phase
planner = MPCPlanner(project)

main_symbol = project.loader.find_symbol('main')

if not main_symbol:
    print("[-] 'main' symbol not found. Is the binary stripped?")
    
main_addr = project.entry
# main_addr = main_symbol.rebased_addr
print(f"[*] Analysis started from main at {hex(main_addr)}")


for name, target_addr in targets:
    print(f"\n[!] Target identified: {name} at {hex(target_addr)}")
    
    results = planner.find_all_paths(main_addr, target_addr)
    sorted_ms = results['milestones'] 

   

    arg1 = claripy.BVS('arg1', 16 * 8) # 16 bytes for buffer
    arg2 = claripy.BVS('arg2', 4 * 8)  # enough for atoi
    arg3 = claripy.BVS('arg3', 4 * 8)

    state = project.factory.full_init_state(
    args=[binary_path, arg1, arg2, arg3],
    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS, 
                 angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY}
    )

    state.add_constraints(arg3 == "42\0\0")
    
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    
    dse = DirectedSearch(sorted_ms, target_addr)
    simgr.use_technique(dse)
    
    print(f"[*] Starting Directed Search for {name}...")
    simgr.run()

    scanner = VulnerabilityScanner(project)
    scanner.scan(simgr)

    if simgr.deadended:
        print(f"[DEBUG] Last deadended address: {hex(simgr.deadended[-1].addr)}")

    # check the result for this specific target
    if simgr.active: # or simgr.found, depends on the implementation of the technique
        print(f"[***] VICTORY: Reached {name} at {hex(target_addr)}")
    
    print(f" - Corridor: {len(results['corridor'])} | Milestones: {len(results['milestones'])}")
