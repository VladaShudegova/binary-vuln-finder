import angr
import networkx as nx

class DirectedSearch(angr.ExplorationTechnique):
    """
    Directed search technique for angr.
    Prioritizes states that have a path to the target address in the CFG.
    """

    def __init__(self, cfg, target_addr):
        """
        Initializes the search technique.

        :param cfg: Control Flow Graph (CFG) of the program.
        :param target_addr: Target address to reach.
        """
        super(DirectedSearch, self).__init__()
        self.cfg = cfg
        self.target_addr = target_addr
        # Search for the target node in the graph
        self.target_node = self.cfg.model.get_any_node(target_addr)
        # Create a clean graph for networkx
        self.graph = nx.DiGraph()
        self.graph.add_edges_from(cfg.graph.edges)

    def setup(self, simgr):
        """
        Sets up the simulation manager for the technique.
        Creates a 'deferred' stash for non-promising paths.

        :param simgr: SimulationManager object the technique is applied to.
        """
        # Initialize the list of deferred paths in the simulator stashes
        if 'deferred' not in simgr.stashes:
            simgr.stashes['deferred'] = []

    def step(self, simgr, stash='active', **kwargs):
        """
        Performs one simulation step and filters states by distance to the target.

        :param simgr: Simulation manager.
        :param stash: Name of the stash to draw states from (defaults to 'active').
        :param kwargs: Additional arguments for the standard angr step.
        :return: Updated SimulationManager.
        """
        # Base simulator step
        simgr = simgr.step(stash=stash, **kwargs)

        # Analyze all active states
        active_states = simgr.stashes[stash]
        new_active = []
        for state in active_states:
            # Calculate distance to target
            dist = self._get_distance(state.addr)
            state.priority = dist 

            # If the state is in a system library (address not in CFG),
            # it is NOT deferred, as it might return to main.
            current_node = self.cfg.model.get_any_node(state.addr)

            self._log_distance(state.addr, dist)
            
            if dist == float('inf') and current_node is not None:
                # If target is unreachable, move state to deferred
                print(f"[*] Block {hex(state.addr)} leads to a dead end. Postponement.")
                simgr.stashes['deferred'].append(state)
            else:
                print(f"[*] Block {hex(state.addr)} at distance {dist} from target. Continue.")
                new_active.append(state)
        
        # Sort active states by distance (Best-First Search)
        new_active.sort(key=lambda s: s.priority)
        # Update the active states stash
        simgr.stashes[stash] = new_active
        return simgr
    
    def _get_distance(self, current_addr):
        """
        Calculates the shortest distance from the current address to the target.
    
        :param current_addr: Current instruction address (int).
        :return: Number of blocks to target or float('inf') if no path exists.
        """
        current_node = self.cfg.model.get_any_node(current_addr)
        if not current_node or not self.target_node:
            return float('inf')  # Node not found, considered unreachable
        try:
            # Count blocks to target using BFS on the graph
            return nx.shortest_path_length(self.graph, current_node, self.target_node)
        except nx.NetworkXNoPath:
            return float('inf')
    
    def _log_distance(self, addr, dist):
        """
        Visualizes analysis progress in the console.
        
        :param addr: Current instruction address (int).
        :param dist: Distance to the target block in graph nodes.
        """
        dist_str = str(dist) if dist != float('inf') else "UNKNOWN (external)"
        print(f"[*] Current address: {hex(addr)} | Distance to target: {dist_str}")
