import logging
import networkx as nx

# setting up logging to see what's happening inside the planner
logger = logging.getLogger("MPCPlanner")
logger.setLevel(logging.INFO)

class MPCPlanner:
    """
    MPCPlanner is responsible for static analysis-based path planning.
    It builds a Control Flow Graph (CFG) and identifies critical nodes
    to guide the Symbolic Execution engine.
    """
     
    def __init__(self, project):
        self.project = project
        self.cfg = self.project.analyses.CFGFast(resolve_indirect_jumps=True)
        self.graph = nx.DiGraph()
        self.graph.add_edges_from(self.cfg.graph.edges)


    def find_all_paths(self, start_addr, target_addr):
        """
        Analyzes the CFG to find the reachability corridor, dominators (milestones),
        and blocks with indirect jumps.

        :param start_addr: Entry point address (e.g., main)
        :param target_addr: Address of the vulnerable function/instruction
        :return: Dictionary containing 'corridor', 'milestones', and 'uncertain' sets
        """
        graph = self.graph 

        start_node = self.cfg.model.get_any_node(start_addr)
        target_node = self.cfg.model.get_any_node(target_addr)
        
        result = {
            'corridor': set(),
            'milestones': set(),
            'uncertain': set()
        }

        if not start_node or not target_node:
            logger.warning(f"Start node {hex(start_addr)} or Target node {hex(target_addr)} not found in CFG.")
            return result
        
        if start_node not in graph or target_node not in graph:
            print("[-] Nodes found in CFG but missing in DiGraph structure.")
            return result

        try:
            # calculate reachability corridor using set intersection
            # 'forward' contains all nodes reachable from start
            forward = nx.descendants(graph, start_node) | {start_node}
            # 'backward' contains all nodes that can eventually reach the target
            backward = nx.ancestors(graph, target_node) | {target_node}
            
            corridor_nodes = forward.intersection(backward)
            result['corridor'] = {n.addr for n in corridor_nodes}

            # identify "uncertain" nodes (indirect jumps outside the corridor)
            # these are blocks that might lead to the target via dynamic resolution
            for node in forward:
                if node not in corridor_nodes:
                    if self._has_indirect_jump(node):
                        result['uncertain'].add(node.addr)

            # calculate Milestones (Immediate Dominators)
            if corridor_nodes:
                result['milestones'] = self._get_milestones(corridor_nodes, start_node, target_node)

        except nx.NetworkXError as e:
            logger.error(f"Graph analysis failed due to NetworkX error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during MPC planning: {e}", exc_info=True)
            
        return result

    def _get_milestones(self, corridor_nodes, start_node, target_node):
        """
        Finds mandatory nodes that every path in the corridor must pass through.
        """
        milestones = set()
        try:
            # create a subgraph containing only "legal" nodes
            subgraph = self.graph.subgraph(corridor_nodes)
            # calculate immediate dominators
            doms = nx.immediate_dominators(subgraph, start_node)
            
            curr = target_node
            # trace back from target to start using dominator tree
            while curr != start_node:
                milestones.add(curr.addr)
                curr = doms[curr]
            milestones.add(start_node.addr)
            return self._get_sorted_milestones(milestones, start_node)
        except Exception as e:
            logger.warning(f"Error calculating milestones: {e}")
            return list(milestones)
    
    
    def _has_indirect_jump(self, node):
        """
        Checks if the basic block ends with an indirect jump/call
        Example: call rax, jmp rdx
        """
        try:
            if not node.block:
                return False

            last_inst = node.block.capstone.insns[-1]
            mnemonic = last_inst.mnemonic
            return mnemonic in ['call', 'jmp'] and len(last_inst.operands) > 0 and last_inst.operands[0].type == 1 # X86_OP_REG
        except Exception:
            return False

    def find_array_access_targets(self, func_addr):
        """
        Умный планер: собирает инструкции обращения к массиву только тогда, 
        когда они не защищены проверками границ (исключает ложные вехи в _good ветках).
        """
        cfg = self.project.analyses.CFGFast()
        func = cfg.functions.get(func_addr)
        if not func:
            return []

        array_targets = []

        # Обходим все базовые блоки внутри функции
        for block in func.blocks:
            # Проверяем, есть ли в текущем блоке инструкции сравнения/валидации
            has_bounds_check = False
            for insn in block.capstone.insns:
                # Ищем инструкции сравнения, которые компилятор ставит для "if (index < size)"
                if insn.mnemonic in ['cmp', 'test']:
                    has_bounds_check = True
                    break

            # Если блок содержит проверку границ, мы полностью ИГНОРИРУЕМ его инструкции массива.
            # Это защитит нас от построения путей до безопасных Good Sinks.
            if has_bounds_check:
                continue

            # Если блок "чистый" (без проверок), ищем в нем инструкции обращения к памяти
            for insn in block.capstone.insns:
                op_str = insn.op_str
                if "[" in op_str and ("*" in op_str or "+" in op_str):
                    # Дополнительный фильтр: исключаем системные обращения к кадру стека (ebp/esp)
                    if "ebp" not in op_str and "esp" not in op_str:
                        array_targets.append(insn.address)

        return array_targets


    def _get_sorted_milestones(self, milestones, start_node):
        """
        Sorts milestones by distance from the entry point to ensure linear progression.
        """
        milestone_nodes = [self.cfg.model.get_any_node(addr) for addr in milestones]
        # filter out None nodes 
        milestone_nodes = [n for n in milestone_nodes if n is not None]

        # sort by shortest path length from start_node
        try:
            sorted_nodes = sorted(
                milestone_nodes, 
                key=lambda n: nx.shortest_path_length(self.graph, start_node, n)
            )
            return [n.addr for n in sorted_nodes]
        except Exception as e:
            logger.warning(f"Failed to sort milestones: {e}. Using unsorted set.")
            return list(milestones)


