import angr
import networkx as nx

class DirectedSearch(angr.ExplorationTechnique):
    """
    Техника направленного поиска для angr.
    Отдает приоритет состояниям, которые имеют путь до целевого адреса в CFG.
    """

    def __init__(self, cfg, target_addr):
        """
        Инициализирует технику поиска.

        :param cfg: Граф потока управления (Control Flow Graph) программы.
        :param target_addr: Целевой адрес, которого нужно достичь.
        """

        super(DirectedSearch, self).__init__()
        self.cfg = cfg
        self.target_addr = target_addr
        # поиск целевого узела в графе
        self.target_node = self.cfg.model.get_any_node(target_addr)
        # создается чистый граф для networkx
        self.graph = nx.DiGraph()
        self.graph.add_edges_from(cfg.graph.edges)

    def setup(self, simgr):
        """
        Настраивает менеджер симуляции для работы с техникой.
        Создает хранилище 'deferred' для неперспективных путей.

        :param simgr: Объект SimulationManager, к которому применяется техника.
        """

        # инициализируется список отложенных путей в хранилизах симулятора
        if 'deferred' not in simgr.stashes:
            simgr.stashes['deferred'] = []

    def step(self, simgr, stash='active', **kwargs):
        """
        Выполняет один шаг симуляции и фильтрует состояния по дистанции до цели.

        :param simgr: Менеджер симуляции.
        :param stash: Имя хранилища, из которого берутся состояния (по умолчанию 'active').
        :param kwargs: Дополнительные аргументы для стандартного шага angr.
        :return: Обновленный SimulationManager.
        """

        # базовый шаг симулятора
        simgr = simgr.step(stash = stash, **kwargs)

        # анализ всех активных состояний
        active_states = simgr.stashes[stash]
        new_active = []
        for state in active_states:
            # получение расстояния до цели
            dist = self._get_distance(state.addr)

            state.priority = dist 
            
            # если состояние находится в системной библиотеке (адрес не в CFG),
            # оно НЕ откладывается, а может вернуться в main.
            current_node = self.cfg.model.get_any_node(state.addr)

            self._log_distance(state.addr, dist)
            
            if dist == float('inf') and current_node is not None:
                # если цель недостижима, перемещаем состояние в отложенные
                print(f"[*] Block {hex(state.addr)} leads to a dead end. Postponement.")
                simgr.stashes['deferred'].append(state)
            else:
                print(f"[*] Block {hex(state.addr)} at distance {dist} from target. Continue.")
                new_active.append(state)
        
        #сортировка активных состояний по расстоянию до цели
        new_active.sort(key=lambda s: s.priority)
        # обновление списка активных состояний
        simgr.stashes[stash] = new_active
        return simgr
    
    def _get_distance(self, current_addr):
        """
        Рассчитывает кратчайшее расстояние от текущего адреса до цели.
    
        :param current_addr: Адрес текущей инструкции (int).
        :return: Количество блоков до цели или float('inf'), если пути нет.
        """

        current_node = self.cfg.model.get_any_node(current_addr)
        if not current_node or not self.target_node:
            return float('inf')  # если узел не найден, он считается недостижимым
        try:
             # подсчет количества блоков до цели с помощью BFS в графе
            return nx.shortest_path_length(self.graph, current_node, self.target_node)
        except nx.NetworkXNoPath:
            return float('inf')
    
    def _log_distance(self, addr, dist):
        """
        Визуализирует прогресс анализа в консоли.
        
        :param addr: Текущий адрес исполняемой инструкции (int).
        :param dist: Расстояние до целевого блока в количестве узлов графа. 
                     Если путь не найден в CFG, принимает значение float('inf').
        """
        dist_str = str(dist) if dist != float('inf') else "UNKNOWN (external)"
        print(f"[*] Текущий адрес: {hex(addr)} | Дистанция до strcpy: {dist_str}")

