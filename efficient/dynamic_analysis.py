import logging
import angr
import sys

logger = logging.getLogger("DirectedSearch")

class DirectedSearch(angr.ExplorationTechnique):
    """
    Checkpoint-based guided search. 
    Divides the global goal into sub-goals (milestones).
    """
    def __init__(self, sorted_milestones, final_target):
        super(DirectedSearch, self).__init__()
        self.milestones = sorted_milestones
        self.final_target = final_target
        self.current_idx = 0
        self.total_steps = len(sorted_milestones)

    def _draw_progress(self, current_addr):
        """Visualizes the progress of checkpoint completion."""
        filled = "=" * self.current_idx
        empty = "-" * (self.total_steps - self.current_idx)
        percent = (self.current_idx / self.total_steps) * 100 if self.total_steps > 0 else 100
        
        sys.stdout.write(f"\r[DSE Progress] [{filled}{empty}] {percent:.1f}% | Target: {hex(current_addr)}")
        sys.stdout.flush()

    def step(self, simgr, stash='active', **kwargs):
        
        if len(simgr.active) > 0:
            logger.info(f"[DEBUG] Current IP: {hex(simgr.active[0].addr)} | Index: {self.current_idx}")
        else:
            logger.warning(f"[DEBUG] NO ACTIVE STATES! Check errored: {len(simgr.errored)} or deadended: {len(simgr.deadended)}")
            if simgr.errored:
                logger.error(f"[DEBUG] Error: {simgr.errored[0].error}")
       

        if not simgr.stashes[stash]:
            return simgr
        
        
        if not simgr.stashes[stash]:
            return simgr
        
        if self.current_idx < len(self.milestones):
            target = self.milestones[self.current_idx]
        else:
            target = self.final_target
        
       
        if self.current_idx >= len(self.milestones):
            logger.info("[*] Navigation complete. Free movement of angr inside vulnerability.bad()")
            return simgr.step(stash=stash, **kwargs)
        

                # Условие Б: Наша текущая цель — это уже финальная функция bad()
        if target == self.final_target:
            logger.info("[*] Final target close. Forcing deep free execution inside bad().")
            
            # Делаем один шаг, чтобы физически переступить порог функции bad() (сесть на адрес 0x80492d0)
            simgr.step(**kwargs)
            
            # Включаем глубокий пошаговый прогон (до 40 шагов), чтобы angr 
            # гарантированно дошел до внутренних инструкций массива (0x80492e7 и далее)
            # и успел вызвать переполнение или краш памяти
            for _ in range(40):
                if len(simgr.active) == 0:
                    break
                simgr.step(**kwargs)
                
            # Возвращаем менеджер, наполненный результатами глубокого прогона
            return simgr


        if self.current_idx == 0:
            state = simgr.stashes[stash][0]
            if state.addr == self.milestones[0]:
                logger.info(f"[*] Force started from main {hex(state.addr)}. Moving to next milestone.")
                self.current_idx = 1
                return simgr.step(stash=stash, **kwargs)
            
        # find=target makes angr search this addres
        simgr.explore(find=target, n=1)

        # if find cheackpoint
        if simgr.found:
            self.current_idx += 1
            self._draw_progress(target)
            
            simgr.move('found', 'active')
            
            
            next_target = self.milestones[self.current_idx] if self.current_idx < len(self.milestones) else self.final_target
            print(f"\n[+] Checkpoint {self.current_idx} reached at {hex(target)}!")
            print(f"[+] Moving to Step {self.current_idx + 1}. Next goal: {hex(next_target)}")

            if next_target == self.final_target:
                print("[*] Final target close! Forcing deep free execution inside bad() right now.")

                if len(simgr.active) == 0 and len(simgr.found) > 0:
                    simgr.move('found', 'active')

                for step_num in range(150):
                    # Печатаем мини-дебаг, чтобы видеть движение angr глазами
                    print(f"  [Free Step {step_num}] Active states: {len(simgr.active)} | Errored: {len(simgr.errored)}")
                    
                    if len(simgr.active) == 0:
                        print("  [!] Active states dropped to 0 during free run. Breaking.")
                        break
                        
                    # Шагаем строго по стэшу active
                    simgr.step(stash='active', **kwargs)

                return simgr
        
            return simgr.step(stash='active', **kwargs)

        # deadlock
        if not simgr.active and not simgr.found:
            print(f"\n[!] DSE stalled at step {self.current_idx}. Active states: 0")
            print(f"[!] Target was: {hex(target)}")
            if simgr.errored:
                print(f"[!] Found {len(simgr.errored)} errors (crashes). Check them for potential exploits!")
            return simgr

        return simgr
