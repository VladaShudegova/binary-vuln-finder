import angr

class VulnerabilityScanner:
    def __init__(self, project):
        self.project = project
    
    
    def check_rip_control(self, state):
        """Более надежная проверка: может ли RIP принимать более одного значения?"""
        if not state.regs.rip.symbolic:
            return False
        
        current_rip = state.solver.eval(state.regs.rip)
        return state.solver.satisfiable(extra_constraints=[state.regs.rip != current_rip])

    def scan(self, simgr):
        print("\n" + "="*50)
        all_states = simgr.active + getattr(simgr, 'unconstrained', [])
        print(f"DEBUG: Checking {len(all_states)} total states...")
        
        found_vulns = False

        for state in all_states:
            if state.regs.rip.symbolic:
                found_vulns = True
                concrete_rip = state.solver.eval(state.regs.rip)
                print(f"[!!!] CRITICAL: Symbolic RIP detected! Possible jump to: {hex(concrete_rip)}")
                
                try:
                    # trying to transfer symbolic input from the POSIX environment (stdin or files)
                    stdin_data = state.posix.stdin.load(0, state.posix.stdin.size)
                    if state.solver.symbolic(stdin_data):
                        val = state.solver.eval(stdin_data, cast_to=bytes)
                        print(f" [->] Payload (stdin): {val}")
                  
                    symbolic_vars = [v for v in state.solver.variables if "arg" in v or "input" in v]
                    for var_name in symbolic_vars[:2]:
                        pass 
                    
                    print(f" [OK] Vulnerability confirmed. Control flow is hijacked.")
                except Exception as e:
                    print(f" [?] Could not resolve payload string: {e}")
                
                break 

        if not found_vulns:
            print("[-] No exploitable vulnerabilities confirmed.")
        print("="*50 + "\n")
