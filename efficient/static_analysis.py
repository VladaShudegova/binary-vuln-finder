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
        except KeyError as e:
            logger.debug(f"Dominator path broken: node {e} not found. Graph might be disconnected.")
        except Exception as e:
            logger.warning(f"Could not calculate milestones: {e}")
            
        return milestones
    
    
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

