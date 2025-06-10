#!/usr/bin/env python3
"""
Детектор отладчиков для Linux систем
"""

import os
import ctypes
import time
from pathlib import Path

class DebuggerDetector:
    def __init__(self):
        self.last_check_time = 0
        self.check_interval = 1.0  # Интервал проверки в секундах
    
    def check_debugger(self):
        """Основная функция проверки на наличие отладчика"""
        current_time = time.time()
        if current_time - self.last_check_time < self.check_interval:
            return False
        
        self.last_check_time = current_time
        
        # Комбинированная проверка различными методами
        return (
            self._check_ptrace() or
            self._check_proc_status() or
            self._check_timing_attack() or
            self._check_parent_process()
        )
    
    def _check_ptrace(self):
        """Проверка через ptrace - если процесс уже отлаживается, ptrace вернет ошибку"""
        try:
            # Попытка присоединиться к самому себе через ptrace
            libc = ctypes.CDLL("libc.so.6")
            PTRACE_TRACEME = 0
            
            # Если возвращает -1, значит процесс уже отлаживается
            result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            if result == -1:
                return True
            
            # Если ptrace прошел успешно, отключаемся
            PTRACE_DETACH = 17
            libc.ptrace(PTRACE_DETACH, 0, 0, 0)
            return False
            
        except Exception:
            # Если не удалось выполнить ptrace, считаем что отладчика нет
            return False
    
    def _check_proc_status(self):
        """Проверка через /proc/self/status - поле TracerPid"""
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        tracer_pid = int(line.split()[1])
                        # Если TracerPid != 0, значит процесс отлаживается
                        return tracer_pid != 0
        except Exception:
            pass
        return False
    
    def _check_timing_attack(self):
        """Проверка через измерение времени выполнения"""
        try:
            # Измеряем время выполнения простой операции
            start_time = time.perf_counter()
            
            # Простая операция для измерения
            dummy_var = 0
            for i in range(1000):
                dummy_var += i
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            # Если время выполнения слишком большое, возможно присутствует отладчик
            # Пороговое значение может потребовать калибровки
            threshold = 0.01  # 10 миллисекунд
            return execution_time > threshold
            
        except Exception:
            return False
    
    def _check_parent_process(self):
        """Проверка родительского процесса на подозрительные имена"""
        try:
            # Получаем PID родительского процесса
            ppid = os.getppid()
            
            # Читаем имя родительского процесса
            with open(f'/proc/{ppid}/comm', 'r') as f:
                parent_name = f.read().strip()
            
            # Список подозрительных имен процессов
            suspicious_names = [
                'gdb', 'strace', 'ltrace', 'valgrind',
                'radare2', 'r2', 'ida', 'ghidra',
                'x64dbg', 'ollydbg', 'immunity'
            ]
            
            return parent_name.lower() in suspicious_names
            
        except Exception:
            return False
    
    def get_detection_info(self):
        """Получение детальной информации о методах детекции"""
        info = {
            'ptrace_check': self._check_ptrace(),
            'proc_status_check': self._check_proc_status(),
            'timing_check': self._check_timing_attack(),
            'parent_process_check': self._check_parent_process()
        }
        return info