import angr
import claripy
import sys

binary_path = "./test_elf"

project = angr.Project(binary_path, auto_load_libs=False)

# Поиск адреса функции strcpy в таблице импорта.
# Это одна из возможных "опасных" точек.
strcpy_plt = project.loader.find_symbol('strcpy').rebased_addr

if strcpy_plt is None:
    print("Не удалось найти символ strcpy. Что-то пошло не так.")
    sys.exit(1)

print(f"Цель найдена: вызов strcpy находится по адресу {hex(strcpy_plt)}")

sym_arg_size = 30 
symbolic_arg = claripy.BVS("sym_arg_1", 8 * sym_arg_size)

initial_state = project.factory.full_init_state(
    args=['./test_elf', symbolic_arg]
)

# Создаем менеджер симуляции
simgr = project.factory.simulation_manager(initial_state)


# Поиск пути, который дойдет до вызова strcpy
print("Начинаю символьное выполнение...")
simgr.explore(find=strcpy_plt)

# Проверка результатов
if simgr.found:
    print("\nПуть к уязвимому участку найден!")
    found_state = simgr.found[0]
    
    solution = found_state.solver.eval(symbolic_arg, cast_to=bytes)

    print(f"Чтобы достичь цели, можно передать аргумент: {solution.decode('utf-8', 'ignore')}")
    print(f"В байтовом представлении: {solution}")
else:
    print("\nНе удалось найти путь к цели. Возможно, нужна более сложная стратегия.")