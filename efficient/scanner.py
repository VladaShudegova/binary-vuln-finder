import angr

class VulnerabilityScanner:
    def __init__(self, project):
        self.project = project
    
    
    def check_rip_control(self, state):
        """Automatically checks eip (32-bit) or rip (64-bit) for input control"""
        # Определяем правильное имя регистра указателя инструкций для текущей архитектуры
        pc_reg_name = 'eip' if hasattr(state.regs, 'eip') else 'rip'
        pc_reg = getattr(state.regs, pc_reg_name)

        if not pc_reg.symbolic:
            return False

        current_pc = state.solver.eval(pc_reg)
        return state.solver.satisfiable(extra_constraints=[pc_reg != current_pc])

    def check_array_bounds_overflow(self, state, array_size=10):
        """Smart check: can a symbolic variable used as an index extend beyond the bounds"""
        if hasattr(state, 'error') and state.error is not None:
            return True
        
        if any(bad_tag in str(state.history.descriptions) for bad_tag in ['crash', 'error']):
            return True
        # Объединяем 32-битные и 64-битные регистры. Несуществующие будут безопасно пропущены
        registers_to_check = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'r8', 'r9', 'r10']
        
        for reg_name in registers_to_check:
            if hasattr(state.regs, reg_name):
                try:
                    reg_val = getattr(state.regs, reg_name)
                    if reg_val.symbolic:
                        # Проверяем математически через z3/claripy
                        can_be_negative = state.solver.satisfiable(extra_constraints=[reg_val < 0])
                        can_be_overflow = state.solver.satisfiable(extra_constraints=[reg_val >= array_size])
                        
                        if can_be_negative or can_be_overflow:
                            # 2. Переломный момент: просим солвер найти конкретный ломающий индекс, 
                            # подставив экстремальное условие как целевое
                            if can_be_overflow:
                                target_constraint = reg_val >= array_size
                            else:
                                target_constraint = reg_val < 0
                                
                            # Генерируем конкретное значение регистра, которое ОДНОВРЕМЕННО 
                            # удовлетворяет коду программы И выходит за границы массива
                            concrete_bad_index = state.solver.eval(reg_val, extra_constraints=[target_constraint])
                            
                            # Если солвер смог успешно решить это уравнение, мы принудительно 
                            # закрепляем это ломающее условие в состоянии, чтобы angr сдампил именно рабочий эксплоит
                            state.add_constraints(reg_val == concrete_bad_index)
                            return True
                except AttributeError:
                    continue
        return False




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
