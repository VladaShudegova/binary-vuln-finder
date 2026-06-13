import angr
import time
import sys
import os
import claripy
import shutil
import contextlib

import logging
logging.getLogger('angr').setLevel(logging.CRITICAL)


sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from efficient.static_analysis import MPCPlanner
from efficient.dynamic_analysis import DirectedSearch
from efficient.scanner import VulnerabilityScanner



SELECTIVE_BINARIES = [
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01_good",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_02_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_02_good",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_12_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_12_good",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_15_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_15_good",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_16_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_16_good",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_17_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_17_good",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_18_bad",
    "CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_18_good",

]


INPUT_PATH = "/analyzer/juliet-dynamic/inputs/int_input"
BASE_SELECTIVE_DIR = "/analyzer/juliet-dynamic/bin_selective/"

def init_test_state(project):
    """# Initializing an identical SimFile to ensure experimental consistency"""
    with open(INPUT_PATH, 'rb') as f:
        initial_data = f.read()
    symbolic_size = 1024
    symbolic_input = claripy.BVS('juliet_stdin', symbolic_size * 8)
    sim_file = angr.storage.SimFile(name="stdin", content=symbolic_input, size=symbolic_size)
    
    return project.factory.full_init_state(
        args=[project.filename],
        stdin=sim_file,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.LAZY_SOLVES
        }
    )

def dump_payloads(simgr, project, out_dir):
    """Invokes VulnerabilityScanner to locate vulnerabilities and store payloads"""
    scanner = VulnerabilityScanner(project)
    file_counter = 0
    os.makedirs(out_dir, exist_ok=True)
    
    all_states = simgr.active + getattr(simgr, 'unconstrained', []) + [e.state for e in simgr.errored] + simgr.deadended
    
    for st in all_states:
        rip_or_crash = scanner.check_rip_control(st) or (st in [e.state for e in simgr.errored])
        array_overflow = scanner.check_array_bounds_overflow(st, array_size=10)

        if rip_or_crash or array_overflow:
            try:
                stdin_data = st.posix.stdin.load(0, st.posix.stdin.size)
                concrete_payload = st.solver.eval(stdin_data, cast_to=bytes)
                concrete_payload = concrete_payload.rstrip(b'\x00')
                
                if len(concrete_payload) > 0:
                    out_path = os.path.join(out_dir, f"payload_{file_counter}.bin")
                    with open(out_path, 'wb') as out_f:
                        out_f.write(concrete_payload)
                    file_counter += 1
            except Exception:
                continue
    return file_counter > 0 # Returns True if the vulnerability is successfully FOUND


def run_my_algorithm(binary_path, out_dir):
    """Ваш алгоритм DirectedSearch + Сбор метрик + Сканирование"""
    project = angr.Project(binary_path, auto_load_libs=False, use_sim_procedures=True)
    
    target_addr = None
    for symbol in project.loader.main_object.symbols:
        if symbol.is_function and ("bad" in symbol.name or "badSink" in symbol.name or "good" in symbol.name):
            target_addr = symbol.rebased_addr
            break
            
    main_symbol = project.loader.find_symbol('main')
    main_addr = main_symbol.rebased_addr if main_symbol else project.entry
    
    # Disabling standard output printing during static analysis
    with open(os.devnull, 'w') as f, contextlib.redirect_stdout(f):
        planner = MPCPlanner(project)
        results = planner.find_all_paths(main_addr, target_addr)
        sorted_ms = results['milestones']
    
    state = init_test_state(project)
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    dse = DirectedSearch(sorted_ms, target_addr)
    simgr.use_technique(dse)
    
    visited_blocks = set()
    max_active_states = 0
    start_time = time.time()
    
    # Disabling [DSE Progress] and [Free Step] console logs during simulation
    with open(os.devnull, 'w') as f, contextlib.redirect_stdout(f):
        while len(simgr.active) > 0:
            max_active_states = max(max_active_states, len(simgr.active))
            for s in simgr.active:
                visited_blocks.add(s.addr)
            if time.time() - start_time > 30:
                break
            simgr.step()
        
    execution_time = time.time() - start_time
    
    
    is_found = dump_payloads(simgr, project, out_dir)
    return execution_time, len(visited_blocks), max_active_states, is_found


def run_bfs_algorithm(binary_path, out_dir):
    """Standard BFS traversal + Metrics collection + Instruction scanning"""
    project = angr.Project(binary_path, auto_load_libs=False, use_sim_procedures=True)
    
    target_addr = None
    for symbol in project.loader.main_object.symbols:
        if symbol.is_function and ("bad" in symbol.name or "badSink" in symbol.name or "good" in symbol.name):
            target_addr = symbol.rebased_addr
            break
            
    state = init_test_state(project)
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    
    visited_blocks = set()
    max_active_states = 0
    start_time = time.time()
    
    with open(os.devnull, 'w') as f, contextlib.redirect_stdout(f):
        while len(simgr.active) > 0 and not hasattr(simgr, 'found'):
            max_active_states = max(max_active_states, len(simgr.active))
            for s in simgr.active:
                visited_blocks.add(s.addr)
            if time.time() - start_time > 30:
                break
            simgr.step()
        
        if hasattr(simgr, 'found') and len(simgr.found) > 0:
            simgr.move('found', 'active')
            for _ in range(150):
                if len(simgr.active) == 0:
                    break
                simgr.step(stash='active')
            
    execution_time = time.time() - start_time
    is_found = dump_payloads(simgr, project, out_dir)
    return execution_time, len(visited_blocks), max_active_states, is_found

def run_benchmark_for_arch(arch_folder):
    """ Runs tests for a specific architecture (bin32 or bin64)"""
    
    arch_dir = os.path.join(BASE_SELECTIVE_DIR, arch_folder)

    if not os.path.exists(arch_dir):
        print(f"[!] Директория {arch_dir} не найдена. Пропуск архитектуры {arch_folder}.")
        return

    print("\n" + "="*95)
    print(f" СРАВНИТЕЛЬНЫЙ АНАЛИЗ ДЛЯ АРХИТЕКТУРЫ: {arch_folder.upper()}")
    print("="*95)
    print(f"{'Juliet Binary Name':<42} | {'Algorithm':<10} | {'Time (s)':<9} | {'Blocks':<6} | {'Paths':<5} | {'Bug Found?'}")
    print("="*95)
    
    for bin_name in SELECTIVE_BINARIES:
        full_path = os.path.join(arch_dir, bin_name)
        if not os.path.exists(full_path):
            continue
            
        short_name = bin_name.split("__")[-1]
        
        
        my_out = f"results_exp/{arch_folder}/my_algo/{short_name}"
        bfs_out = f"results_exp/{arch_folder}/bfs/{short_name}"
        
        try:
            t_my, cov_my, max_st_my, found_my = run_my_algorithm(full_path, my_out)
            t_bfs, cov_bfs, max_st_bfs, found_bfs = run_bfs_algorithm(full_path, bfs_out)
            
            status_my = "YES (TP)" if found_my else "NO (TN/FN)"
            status_bfs = "YES (TP)" if found_bfs else "NO (TN/FN)"
            
            print(f"{short_name:<42} | {'Кастомный':<10} | {t_my:<9.2f} | {cov_my:<6} | {max_st_my:<5} | {status_my}")
            print(f"{'':<42} | {'BFS':<10} | {t_bfs:<9.2f} | {cov_bfs:<6} | {max_st_bfs:<5} | {status_bfs}")
            print("-"*95)
        except Exception as e:
            print(f"Error during analysis {short_name}: {e}")

def main():
    if os.path.exists("results_exp"):
        shutil.rmtree("results_exp")
        
    
    run_benchmark_for_arch("bin32")
    run_benchmark_for_arch("bin64")

if __name__ == "__main__":
    main()
