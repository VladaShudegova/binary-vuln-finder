# цель данного скрипта - проанализировать CFG и найти все пути от входа к выходу, а также определить, какие блоки являются критическими для достижения выхода.
import angr
import networkx as nx # импортируем библиотеку для работы с графами


binary_path = "./elf_files/test_elf"
project = angr.Project(binary_path, auto_load_libs=False)

print("Building CFG...")
# каждый базовый блок принадлежит не более чем одной функции, 
# обратные ребра указывают на начало базовых блоков
cfg = project.analyses.CFGFast(normalize=True)
print(f"CFG built. Found {len(cfg.graph.nodes)} nodes and {len(cfg.graph.edges)} edges.")

# поиск узла, соответствующего функции main
main_func = cfg.kb.functions.function(name="main")

if main_func:
    print(f"Function 'main' starts at address: {hex(main_func.addr)}")
    # Подсчет количества базовых блоков в функции main
    print(f"Number of basic blocks in main: {len(main_func.block_addrs)}")

    print(f"Exporting main to DOT file...")
    
    # подграф только для функции main
    main_nodes = [node for node in cfg.graph.nodes if node.addr in main_func.block_addrs]
    main_subgraph = cfg.graph.subgraph(main_nodes)
    
    # cохранение в файл .dot
    # Нам нужно превратить узлы в строки, чтобы Graphviz их понял
    nx.drawing.nx_pydot.write_dot(main_subgraph, "main_cfg.dot")
    print("Done! File 'main_cfg.dot' created.")
   