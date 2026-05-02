import angr
import networkx as nx
import claripy

from techniques import DirectedSearch 

# loading the project and static analysis to obtain CFG
binary_path = "./elf_files/test_elf"
project = angr.Project(binary_path, auto_load_libs=False)

print("Building CFG...")
cfg = project.analyses.CFGFast(normalize=True)

# strcpy search 
strcpy_symbol = project.loader.find_symbol('strcpy')
strcpy_addr = strcpy_symbol.rebased_addr

# search for call points
target_addresses = []
for node in cfg.model.nodes():
    successors = cfg.model.graph.successors(node)
    for succ in successors:
        if succ.addr == strcpy_addr:
            target_addresses.append(node.addr)



# symbolic execution with directed search technique
print("\n[*] Starting directed symbolic execution...")

arg_size = 50 
symbolic_arg = claripy.BVS("input_string", 8 * arg_size)
argc = claripy.BVS("argc", 32)


main_func = project.kb.functions.get("main")
if not main_func:
    print("[-] Failed to find 'main'. Check binary symbols.")
    exit()

state = project.factory.entry_state(
    addr=main_func.addr, 
    args=[binary_path, symbolic_arg],
    add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS # уберет варнинги
    }
)

# forced installation of argc
state.regs.x0 = argc 

simgr = project.factory.simulation_manager(state)


target_addr = target_addresses[0]
search_technique = DirectedSearch(cfg, target_addr)
simgr.use_technique(search_technique)


# finding the path to the goal
simgr.explore(find=target_addr)

print("\n[*] Start direct search...")

# Instead of explore, a loop is used until the target is found or there are no more paths
while simgr.active:
    simgr.step() # здесь автоматически вызывается DirectedSearch.step()
    
    # провнрка достижения состояния цели
    for state in simgr.active:
        if state.addr == target_addr or (state.history.addr and state.history.addr == target_addr):
            print(f"[!] Target {hex(target_addr)} achieved!")
            # перенос состояния в stash 'found' и остановка цикла
            simgr.move('active', 'found', lambda s: s.addr == target_addr)
            break
    
    if simgr.found:
        break


if simgr.found:
    print(f"\n[+] SUCCESS! Target reached.")
else:
    print("\n[-] PATH NOT FOUND. Manager state analysis:")
    print(f" - Deferred/Deadlocks: {len(simgr.stashes['deferred'])} paths")
    print(f" - Deadended: {len(simgr.deadended)} paths")
    
    if simgr.deadended:
        print("\nLast addresses of finished paths (deadended):")
        for s in simgr.deadended:
            print(f" -> {hex(s.addr)}")

    if simgr.stashes['deferred']:
        print("\nReason for deferring the first path:")
        last_state = simgr.stashes['deferred'][0]
        print(f" -> Address: {hex(last_state.addr)}")
        try:
            project.factory.block(last_state.addr).pp()
        except:
            print(" -> Could not read block instructions.")


if simgr.found:
    found_state = simgr.found[0]
    
    
    for i in range(arg_size):
        found_state.add_constraints(symbolic_arg.get_byte(i) >= ord('A'))
        found_state.add_constraints(symbolic_arg.get_byte(i) <= ord('z'))
    
    if found_state.satisfiable():
        result = found_state.solver.eval(symbolic_arg, cast_to=bytes)
        clean_result = result.decode('utf-8', errors='ignore').strip('\x00')
        
        print(f"\n[+] SUCCESS! Directed search found payload:")
        print(f" Argument: {clean_result}")
        print(f" Length: {len(clean_result)} bytes")
        
        
        print(f"\n[*] Algorithm statistics:")
        print(f" - Paths explored: {len(simgr.found) + len(simgr.deadended)}")
        print(f" - Dead-end branches pruned: {len(simgr.stashes['deferred'])}")
    else:
        print("[-] Could not satisfy constraints.")


