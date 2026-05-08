# Development Report: Integration of Static Path Planner (MPC) with Directed Symbolic Execution (DSE)

### 1. Objective

Experimental verification of a hybrid approach for target discovery in binary files. 
The primary goal is to combine preliminary static graph analysis (MPC) with a symbolic execution mechanism to minimize the "state explosion" problem.

### 2. Implemented Modules
#### 2.1 Static Path Planner (`MPCPlanner`)

A module developed for the preliminary analysis of the Control Flow Graph (CFG).

**Functionality:** Takes the CFG and a target address as input. Using graph algorithms, it identifies all basic blocks that potentially lie on the path from the entry point (`main`) to the target.

**Result:** Generates a list of addresses (`static_plan`) that serves as a "roadmap" for the symbolic execution engine.

#### 2.2 Modified Exploration Technique (`DirectedSearch`)

A custom exploration technique for the angr framework, adapted to work with the static plan.

**Logic**: Instead of blind branch traversal, the technique cross-references the current state address with the  `static_plan` at each step.

**Filtering**: If a state deviates from the pre-calculated route, it is marked as non-promising and moved to the archive (`deferred stash`).


### 3. Integration Process (Combining Modules)

The main script `main.py` implements the following interaction workflow:

**CFG Reconstruction**: The project is loaded without shared libraries to accelerate the analysis.

**Data Collection**: Automated calculation of call site addresses for the target function (e.g., `strcpy`).

**Plan Generation**: `MPCPlanner` constructs a list of required basic blocks.

**Symbolic Execution**: A simulation manager (`simgr`) is initialized, and the `DirectedSearch` technique is injected using the data provided by the planner.

**Verification Loop**: A manual execution cycle (`simgr.step()`) is implemented to monitor target achievement and analyze deferred paths continuously.


### 4. Current Results

Successful data transfer between the static and dynamic analysis modules was achieved.

The algorithm successfully identifies the path to the target function in the test binary (`test_elf`).

Payload generation from the found state is implemented, including constraints for printable ASCII characters.

### 5. Conclusion

The combination of MPC and DSE reduced the number of actively processed execution paths. The static plan acts as an efficient filter, pruning code branches that do not lead to the target. This is confirmed by the statistical data (see "Dead-end branches pruned").
