import angr
import claripy
import argparse
import os
import sys
import logging

logging.getLogger('angr').setLevel(logging.CRITICAL)

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from efficient.static_analysis import MPCPlanner
from efficient.dynamic_analysis import DirectedSearch
from efficient.scanner import VulnerabilityScanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--input", required=True)   # Initial valid test case provided by ISP RAS
    parser.add_argument("--outdir", required=True)  # Output directory for storing mutation artifacts
    args = parser.parse_args()

   
    project = angr.Project(args.binary, auto_load_libs=False, use_sim_procedures=True)

    # 1. Automated search for a dangerous function (e.g., strcpy or memcpy)
    # Universal list of dangerous functions for CWE-121
    danger_functions = ['strcpy', 'memcpy', 'sprintf', 'strcat']     
    target_addr = None
    target_func_obj = None

    print("[*] Построение CFG для поиска объектов функций...")
    cfg = project.analyses.CFGFast()

    # Verifying whether the binary imports any dangerous functions through the PLT
    for func_name in danger_functions:
        plt_symbol = project.loader.main_object.plt.get(func_name)
        if plt_symbol is not None:
            target_addr = plt_symbol
            print(f"[!] Цель определена через PLT: функция {func_name} на адресе {hex(target_addr)}")
            break

    if not target_addr:
        for symbol in project.loader.main_object.symbols:
            if symbol.is_function and ("bad" in symbol.name or "badSink" in symbol.name):
                target_addr = symbol.rebased_addr
                print(f"[*] Резервная цель (символ функции): {symbol.name} на {hex(target_addr)}")

                # Retrieving the complete function object from the CFG using its address
                target_func_obj = cfg.functions.get(target_addr)
                break

    if not target_addr:
        # If the binary lacks both dangerous functions and bad(), it is guaranteed to be secure
        sys.exit(0)
    
    print(f"[DEBUG] Найден адрес цели target_addr: {hex(target_addr) if target_addr else 'НЕ НАЙДЕН'}")



    main_symbol = project.loader.find_symbol('main')
    main_addr = main_symbol.rebased_addr if main_symbol else project.entry


    planner = MPCPlanner(project)
    results = planner.find_all_paths(main_addr, target_addr)
    sorted_ms = results['milestones']

    if target_func_obj is not None:
        print(f"[*] Цель является функцией ({target_func_obj.name}). Поиск инструкций работы с массивами...")

        # Passing the function OBJECT (target_func_obj) to the method as expected
        internal_targets = planner.find_array_access_targets(target_func_obj.addr)


        if internal_targets:
            # Appending addresses of internal assembly instructions to the initial milestones            sorted_ms.extend(internal_targets)
            print(f"[+] Граф вех успешно расширен инструкциями массива: {[hex(t) for t in internal_targets]}")


    # Reading initial input and setting up the symbolic POSIX stdin
    with open(args.input, 'rb') as f:
        initial_data = f.read()

    symbolic_size = max(len(initial_data) * 4, 1024)
    symbolic_input = claripy.BVS('juliet_stdin', symbolic_size * 8)

    # Initializing a generic file containing symbolic data
    sim_file = angr.storage.SimFile(name="stdin", content=symbolic_input, size=symbolic_size)

    state = project.factory.full_init_state(
        args=[args.binary],
        stdin=sim_file, # Injecting the symbolic file directly into this argument
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.LAZY_SOLVES
        }
    )

   
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    dse = DirectedSearch(sorted_ms, target_addr)
    simgr.use_technique(dse)

    print(f"[*] Запуск симуляция!")
    simgr.run(timeout=120) # Internal timeout limit per single binary

    print("="*40 + "\n")
    if hasattr(simgr, 'unconstrained'):
        print(f"  Неконтролируемых (unconstrained): {len(simgr.unconstrained)}")
    print("="*40 + "\n")

    # Extracting the mutated input data (payload) responsible for the vulnerability    scanner = VulnerabilityScanner(project)
    scanner = VulnerabilityScanner(project)
    file_counter = 0


    all_states = simgr.active + getattr(simgr, 'unconstrained', []) + [e.state for e in simgr.errored] + simgr.deadended

    for st in all_states:
       
        is_crash = st in [e.state for e in simgr.errored]
        rip_controlled = scanner.check_rip_control(st)
        array_overflow = scanner.check_array_bounds_overflow(st, array_size=10)

        if is_crash or rip_controlled or array_overflow:
                    try:
                        stdin_data = st.posix.stdin.load(0, st.posix.stdin.size)
                        concrete_payload = st.solver.eval(stdin_data, cast_to=bytes)
                        concrete_payload = concrete_payload.rstrip(b'\x00')

                        if concrete_payload != initial_data and len(concrete_payload) > 0:
                            out_path = os.path.join(args.outdir, f"payload_{file_counter}.bin")
                            with open(out_path, 'wb') as out_f:
                                out_f.write(concrete_payload)
                            file_counter += 1
                    except Exception:
                        continue



if __name__ == "__main__":
    main()
