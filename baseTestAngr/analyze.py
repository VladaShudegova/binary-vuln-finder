import angr
import claripy
import sys

binary_path = "./elf_files/test_elf"

# для экономии времени и памяти отключаю анализ системные библиотеки
project = angr.Project(binary_path, auto_load_libs=False)


# ищу адреса функции strcpy в таблице импорта.
# это одна из возможных "опасных" точек.
strcpy_plt = project.loader.find_symbol('strcpy').rebased_addr

if strcpy_plt is None:
    print("Не удалось найти символ strcpy. Что-то пошло не так.")
    sys.exit(1)

print(f"Цель найдена: вызов strcpy находится по адресу {hex(strcpy_plt)}")

sym_arg_size = 30 
symbolic_arg = claripy.BVS("sym_arg_1", 8 * sym_arg_size)

# full_init_state имитирует запуск программы.
# запуск программы с symbolic_arg в качестве первого аргумента
initial_state = project.factory.full_init_state(
    args=[binary_path, symbolic_arg]
)

# менеджер симуляции
simgr = project.factory.simulation_manager(initial_state)


# ищу пути, который дойдет до вызова strcpy
print("Начинаю символьное выполнение...")
simgr.explore(find=strcpy_plt)

# проверяю результат
if simgr.found:
    print("\nПуть к уязвимому участку найден!")
    found_state = simgr.found[0]
    
    solution = found_state.solver.eval(symbolic_arg, cast_to=bytes)

    output = '""' if len(solution) > 0 else solution.decode('utf-8', 'ignore')

    print(f"Чтобы достичь цели, можно передать аргумент: {output}")
    print(f"В байтовом представлении: {solution}")
else:
    print("\nНе удалось найти путь к цели. Возможно, нужна более сложная стратегия.")