import angr
import claripy
from static_analysis import MPCPlanner
from techniques import DirectedSearch
from scanner import VulnerabilityScanner




binary_path = "./elf_files/test_elf"
project = angr.Project(binary_path, auto_load_libs=False)


cfg = project.analyses.CFGFast(normalize=True)


main_func = project.kb.functions.get("main")
if not main_func:
    print("[-] Failed to find 'main'. Check binary symbols.")
    exit()

scanner = VulnerabilityScanner(project, cfg)
targets = scanner.find_targets()

for target in targets:
    print(f"[*] Analyzing potential vulnerability: {target['name']} at address {hex(target['addr'])}")

    #Static analysis to find paths to the target
    planner = MPCPlanner(cfg)
    static_plan = planner.find_all_paths(main_func.addr, target['addr'])
    arg_size = 50 
    symbolic_arg = claripy.BVS("input_string", 8 * arg_size)
    argc = claripy.BVS("argc", 32)
    
    # Dynamic symbolic execution with directed search
    state = project.factory.entry_state(
        addr = main_func.addr, 
        args = [binary_path, symbolic_arg],
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
    )

    state.regs.x0 = argc

    simgr = project.factory.simulation_manager(state)
    simgr.stashes['found'] = [] 
    simgr.use_technique(DirectedSearch(cfg, target['addr'], static_plan))

    simgr.explore(find=target['addr'])

    if simgr.found:
        final_state = simgr.found[0] 

        if scanner.verify_overflow(final_state):
            print(f"[+] Vulnerability confirmed for {target['name']} at {hex(target['addr'])}! \n")
            payload, size = scanner.generate_payload(final_state, symbolic_arg)

            if payload:
                print(f"[!] Generated payload: {payload.decode(errors='ignore')}")
                print(f"[!] Length: {size} bytes")
        else:
            print(f"[-] Failed to confirm vulnerability for {target['name']} at {hex(target['addr'])}.\n")
       

