# Development Report: Implementation of Directed Symbolic Execution (DSE) for Vulnerability Discovery

## 1. Objective
The goal of this stage was to develop a core mechanism for guided binary analysis. 
The focus was on implementing **Directed Symbolic Execution (DSE)** to reach specific "vulnerability sinks" (e.g., `strcpy`) while mitigating the **Path Explosion** problem through heuristic-based graph analysis.

## 2. Implemented Modules

### 2.1 Custom Exploration Technique (`DirectedSearch`)

A specialized exploration class was developed on top of the **angr** framework to override the default path selection logic.

**Prioritization**: The technique ranks active states based on their proximity to the target address in the program's structure.

**State Management**: Introduced a system of "stashes" where promising states remain `active`, while non-promising ones are moved to a `deferred` stash.

### 2.2 Graph-Based Heuristic Engine

To guide the search, a mathematical heuristic was integrated using the **NetworkX** library.

**BFS Algorithm**: The tool treats the program's Control Flow Graph (CFG) as a directed graph $\(G = (V, E)\)$. It uses **Breadth-First Search (BFS)** to calculate the shortest distance $\(L\)$ from the current basic block $\(v_{curr}\)$ to the target $\(v_{target}\)$.

**Path Pruning**: Implemented a pruning mechanism where states with $\(L = \infty\)$ (unreachable targets) are automatically postponed. This significantly reduces the load on the SMT solver and prevents memory exhaustion.

## 3. Workflow

The analysis process follows these technical steps:

1. **Static Analysis**: Generation of a Control Flow Graph (CFG) to map the binary's internal structure.

2. **Target Definition**: Identification of critical function symbols or raw memory addresses.

3. **Heuristic Evaluation**: During each simulation step, the distance to the target is recalculated for every active path.

4. **Directed Execution**: The simulation manager executes the most promising paths first, based on the calculated $\(L\)$ values.

## 4. Key Results

**Path Selection Efficiency**: The algorithm demonstrated the ability to ignore irrelevant code branches (e.g., error handling or unrelated logic).

**Automated Payload Generation**: Successfully integrated **Claripy** to solve path constraints once the target is reached. The tool produces concrete input strings (payloads) restricted to printable ASCII characters.

**Resource Optimization**: Real-time statistics showed a significant decrease in the number of concurrent states compared to standard Breadth-First exploration.

## 5. Tech Stack

- **Python 3.12**
- **angr** (Symbolic Execution Engine)
- **NetworkX** (Graph Algorithms)
- **Claripy** (SMT Solver Wrapper)


## 6. Conclusion
The implementation of DSE proved that using CFG-based heuristics is an effective way to guide symbolic execution. By prioritizing paths based on their distance to the target, the tool successfully reached the vulnerability site and generated a valid exploit payload, confirming the viability of the chosen architectural approach.
