#!/usr/bin/env python3
"""
Скрипт установки для Security Monitor
"""

import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Проверка версии Python"""
    if sys.version_info < (3, 6):
        print("[ERROR] Требуется Python 3.6 или выше")
        print(f"[ERROR] Текущая версия: {sys.version}")
        return False
    return True

def check_os():
    """Проверка операционной системы"""
    if os.name != 'posix':
        print("[WARNING] Утилита оптимизирована для Linux систем")
        print(f"[WARNING] Текущая ОС: {os.name}")
        return False
    return True

def install_requirements():
    """Установка зависимостей"""
    requirements_file = Path(__file__).parent / 'requirements.txt'
    
    if not requirements_file.exists():
        print("[ERROR] Файл requirements.txt не найден")
        return False
    
    try:
        print("[INFO] Установка зависимостей...")
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)
        ])
        print("[INFO] Зависимости установлены успешно")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Ошибка при установке зависимостей: {e}")
        return False

def create_launcher_script():
    """Создание скрипта запуска"""
    launcher_content = '''#!/bin/bash
# Security Monitor Launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Активация виртуального окружения если существует
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Запуск приложения
python3 main.py "$@"
'''
    
    launcher_path = Path(__file__).parent / 'run.sh'
    
    try:
        with open(launcher_path, 'w') as f:
            f.write(launcher_content)
        
        # Делаем скрипт исполняемым
        os.chmod(launcher_path, 0o755)
        print(f"[INFO] Создан скрипт запуска: {launcher_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Ошибка при создании скрипта запуска: {e}")
        return False

def test_imports():
    """Тестирование импортов модулей"""
    print("[INFO] Тестирование импортов...")
    
    try:
        # Добавляем src в путь
        src_path = Path(__file__).parent / 'src'
        sys.path.insert(0, str(src_path))
        
        # Тестируем основные модули
        from detectors.debugger_detector import DebuggerDetector
        from detectors.process_monitor import ProcessMonitor
        from monitoring.system_monitor import SystemMonitor
        
        print("[INFO] Основные модули импортированы успешно")
        
        # Тестируем GUI (может не работать без дисплея)
        try:
            from gui.monitor_window import MonitorWindow
            print("[INFO] GUI модуль импортирован успешно")
        except Exception as e:
            print(f"[WARNING] GUI модуль недоступен: {e}")
        
        return True
        
    except ImportError as e:
        print(f"[ERROR] Ошибка импорта: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Неожиданная ошибка: {e}")
        return False

def main():
    """Основная функция установки"""
    print("=== Security Monitor - Установка ===")
    print()
    
    # Проверки
    if not check_python_version():
        return 1
    
    check_os()  # Предупреждение, но не критично
    
    # Установка зависимостей
    if not install_requirements():
        return 1
    
    # Создание скрипта запуска
    create_launcher_script()
    
    # Тестирование
    if not test_imports():
        print("[WARNING] Некоторые модули могут работать некорректно")
    
    print()
    print("=== Установка завершена ===")
    print()
    print("Для запуска используйте:")
    print("  python3 main.py --gui      # С графическим интерфейсом")
    print("  python3 main.py --console  # В консольном режиме")
    print("  ./run.sh --gui             # Через скрипт запуска")
    print()
    print("Для получения справки:")
    print("  python3 main.py --help")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())