import networkx as nx

class MPCPlanner:
    """
    MPCPlanner is a class that implements a Model Predictive Control (MPC) planner for directed symbolic execution.
    It uses a control flow graph (CFG) to guide the search towards a target address.
    """

    def __init__(self, cfg):
        """
        Initializes the MPCPlanner.

        :param cfg: Control Flow Graph (CFG) of the program.
        :param target_addr: Target address to reach.
        """
        self.cfg = cfg
        self.graph = nx.DiGraph()
        self.graph.add_edges_from(cfg.graph.edges)

    def find_all_paths(self, start_addr, target_addr):
        """
        Finds all paths in the CFG.

        :param start_addr: Starting address.
        :param target_addr: Target address.
        :return: List of all paths from start to target.
        """

        start_node = self.cfg.model.get_any_node(start_addr)
        target_node = self.cfg.model.get_any_node(target_addr)

        if not start_node or not target_node:
            print("[-] Start or target node not found in CFG.")
            return set()
        
        # Find all simple paths from start to target
        paths = list(nx.all_simple_paths(self.graph, source=start_node, target=target_node))
        
        all_blocks_on_paths = set()
        for path in paths:
            for node in path:
                all_blocks_on_paths.add(node.addr)

        return all_blocks_on_paths