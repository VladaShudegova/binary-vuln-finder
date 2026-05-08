import angr
import claripy

class VulnerabilityScanner:
    def __init__(self, project, cfg):
        self.project = project
        self.cfg = cfg
        self.dangerous_funcs = ["strcpy", "strcat", "gets", "memcpy", "memmove", "printf", "fprintf", "syslog", "scanf", "free" ]  

    def find_targets(self):
        """Finding dangerous function calls in your code"""
        targets = []
        for func_name in self.dangerous_funcs:
            symbol = self.project.loader.find_symbol(func_name)
            if symbol:
                plt_addr = symbol.rebased_addr
                # Search for nodes that reference an address in the PLT
                for node in self.cfg.model.nodes():
                    # Check all the "heirs" of the block
                    for succ in self.cfg.model.graph.successors(node):
                        if succ.addr == plt_addr:
                            targets.append({'name': func_name, 'addr': node.addr})
        return targets
    
    # def verify_overflow(self, state):
    #     """Check if the state can lead to a buffer overflow by analyzing constraints on symbolic variables."""
    #     return state is not None
    
    # def generate_payload(self, state, symbolic_variable):
    #     """Generate a payload that satisfies the constraints of the symbolic variable"""
    #     final_state = state.copy()
        
    #     for i in range(symbolic_variable.size() // 8):
    #         final_state.add_constraints(symbolic_variable.get_byte(i) >= ord('A'))
    #         final_state.add_constraints(symbolic_variable.get_byte(i) <= ord('z'))
        
    #     if final_state.satisfiable():
    #         result = final_state.solver.eval(symbolic_variable, cast_to=bytes)
    #         return result, len(result)
        
    #     return None, 0

    def verify_overflow(self, state):
        """
        Проверяет, привело ли состояние к возможности переполнения.
        Для ARM64 проверяем Link Register (x30) и PC.
        """
        if state is None:
            return False

        # 1. Проверяем, стал ли указатель команд символьным (прямой контроль исполнения)
        if state.solver.symbolic(state.regs.pc):
            return True

        # 2. Для ARM64/AArch64 проверяем Link Register (x30), куда сохраняется адрес возврата
        if hasattr(state.regs, 'x30') and state.solver.symbolic(state.regs.x30):
            return True
            
        # 3. Проверяем область стека (если данные перезаписали место для сохраненного PC)
        stack_ptr = state.regs.sp
        stack_content = state.memory.load(stack_ptr, 64) # Читаем верхушку стека
        if state.solver.symbolic(stack_content):
            return True

        return False
    
    def generate_payload(self, state, symbolic_variable):
        """
        Динамически определяет минимальный размер payload для вызова переполнения.
        """
        found_size = 0
        max_bytes = symbolic_variable.size() // 8

        # Ищем минимальный размер, который влияет на управление
        for size in range(1, max_bytes + 1):
            test_state = state.copy()
            if test_state.solver.symbolic(test_state.regs.pc) or \
               (hasattr(test_state.regs, 'x30') and test_state.solver.symbolic(test_state.regs.x30)):
                found_size = size
                break
        
        if found_size == 0:
            found_size = max_bytes

        final_state = state.copy()
        # ИСПРАВЛЕНО: используем переменную из аргументов функции (symbolic_variable)
        for i in range(found_size):
            final_state.add_constraints(symbolic_variable.get_byte(i) >= ord('A'))
            final_state.add_constraints(symbolic_variable.get_byte(i) <= ord('z'))
        
        if final_state.satisfiable():
            result = final_state.solver.eval(symbolic_variable, cast_to=bytes)
            clean_result = result[:found_size]
            return clean_result, found_size
        
        return None, 0
