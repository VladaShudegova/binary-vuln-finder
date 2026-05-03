# Binary Vulnerability Finder (Directed Symbolic Execution)

This project implements a binary analysis tool based on the **angr** framework, designed to find vulnerabilities (such as buffer overflows) using **Directed Symbolic Execution**.

## Key Features

 **Custom Exploration Technique**: Implements a `DirectedSearch` class that prioritizes execution paths leading to a specific target (e.g., `strcpy`, `system`).
 
 **Path Pruning**: Automatically detects and postpones "dead-end" paths using Control Flow Graph (CFG) analysis to solve the **Path Explosion** problem.
 
 **BFS-based Heuristics**: Uses the Breadth-First Search algorithm (via `NetworkX`) to calculate the shortest distance between the current state and the vulnerability site.
 
 **Automated Payload Generation**: When a target is reached, the tool automatically calculates the necessary input string (payload) to trigger the state.

## Mathematical Background

The core of the tool is a heuristic function $L = dist(v_{curr}, v_{target})$. 
1. It treats the program as a directed graph $G = (V, E)$.
2. It uses **BFS** to find the shortest path in the CFG.
3. States with $L = \infty$ are moved to a `deferred` stash, significantly reducing memory consumption and SMT solver load.

## Tech Stack

- **Python 3.12**
- **angr** (Symbolic Execution Engine)
- **NetworkX** (Graph Algorithms)
- **Claripy** (SMT Solver Wrapper)


## Statistics Output
The tool provides real-time console feedback:
 **Paths explored**: Total number of execution states analyzed.
 **Dead-end branches pruned**: Number of non-promising paths successfully filtered out.
 **Payload**: The specific input required to reach the target function.
