#!/usr/bin/env python3
"""
Мониторинг процессов для обнаружения инструментов реверс-инжиниринга
"""

import os
import psutil
import time
from pathlib import Path

class ProcessMonitor:
    def __init__(self):
        self.suspicious_processes = set()
        self.last_scan_time = 0
        self.scan_interval = 2.0  # Интервал сканирования в секундах
        
        # Список подозрительных процессов и инструментов
        self.blacklist = {
            # Отладчики
            'gdb', 'gdb-multiarch', 'cgdb', 'ddd',
            'lldb', 'pdb', 'windbg',
            
            # Трассировщики
            'strace', 'ltrace', 'ftrace', 'dtrace',
            'ptrace', 'systrace',
            
            # Дизассемблеры и реверс-инжиниринг
            'radare2', 'r2', 'rizin', 'cutter',
            'ghidra', 'ida', 'ida64', 'idaq', 'idaq64',
            'x64dbg', 'x32dbg', 'ollydbg', 'immunity',
            'hopper', 'binary ninja', 'binaryninja',
            
            # Анализаторы памяти
            'valgrind', 'memcheck', 'helgrind', 'cachegrind',
            'massif', 'drmemory', 'addresssanitizer',
            
            # Инструменты анализа
            'objdump', 'readelf', 'nm', 'strings',
            'hexdump', 'xxd', 'od', 'hexedit',
            
            # Сетевые анализаторы
            'wireshark', 'tshark', 'tcpdump', 'nmap',
            'netstat', 'ss', 'lsof',
            
            # Инструменты для взлома
            'john', 'hashcat', 'hydra', 'medusa',
            'aircrack-ng', 'reaver', 'bettercap',
            
            # Фреймворки тестирования
            'metasploit', 'msfconsole', 'msfvenom',
            'armitage', 'cobalt strike',
            
            # Инструменты Kali Linux
            'burpsuite', 'zaproxy', 'sqlmap', 'nikto',
            'dirb', 'gobuster', 'wfuzz', 'ffuf'
        }
        
        # Подозрительные пути
        self.suspicious_paths = {
            '/usr/bin/gdb',
            '/usr/bin/strace',
            '/usr/bin/ltrace',
            '/opt/ghidra',
            '/opt/ida',
            '/usr/share/radare2',
            '/usr/share/metasploit-framework'
        }
    
    def scan_processes(self):
        """Сканирование запущенных процессов"""
        current_time = time.time()
        if current_time - self.last_scan_time < self.scan_interval:
            return list(self.suspicious_processes)
        
        self.last_scan_time = current_time
        current_suspicious = set()
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    proc_info = proc.info
                    if self._is_suspicious_process(proc_info):
                        process_desc = self._format_process_info(proc_info)
                        current_suspicious.add(process_desc)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            print(f"[ERROR] Ошибка при сканировании процессов: {e}")
        
        # Обновляем список подозрительных процессов
        new_processes = current_suspicious - self.suspicious_processes
        self.suspicious_processes = current_suspicious
        
        return list(new_processes)
    
    def _is_suspicious_process(self, proc_info):
        """Проверка, является ли процесс подозрительным"""
        if not proc_info:
            return False
        
        # Проверка имени процесса
        proc_name = proc_info.get('name', '').lower()
        if proc_name in self.blacklist:
            return True
        
        # Проверка пути к исполняемому файлу
        proc_exe = proc_info.get('exe', '')
        if proc_exe:
            exe_name = os.path.basename(proc_exe).lower()
            if exe_name in self.blacklist:
                return True
            
            # Проверка подозрительных путей
            for suspicious_path in self.suspicious_paths:
                if proc_exe.startswith(suspicious_path):
                    return True
        
        # Проверка аргументов командной строки
        cmdline = proc_info.get('cmdline', [])
        if cmdline:
            cmdline_str = ' '.join(cmdline).lower()
            
            # Поиск подозрительных ключевых слов в аргументах
            suspicious_keywords = [
                'attach', 'debug', 'trace', 'dump',
                'disasm', 'reverse', 'crack', 'exploit'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in cmdline_str:
                    return True
        
        return False
    
    def _format_process_info(self, proc_info):
        """Форматирование информации о процессе"""
        pid = proc_info.get('pid', 'N/A')
        name = proc_info.get('name', 'N/A')
        exe = proc_info.get('exe', 'N/A')
        
        return f"{name} (PID: {pid}) - {exe}"
    
    def get_all_suspicious_processes(self):
        """Получение всех текущих подозрительных процессов"""
        return list(self.suspicious_processes)
    
    def is_process_running(self, process_name):
        """Проверка, запущен ли конкретный процесс"""
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() == process_name.lower():
                    return True
        except Exception:
            pass
        return False
    
    def get_process_tree(self, pid):
        """Получение дерева процессов для анализа"""
        try:
            proc = psutil.Process(pid)
            tree = []
            
            # Получаем родительские процессы
            current = proc
            while current.parent() is not None:
                parent = current.parent()
                tree.insert(0, {
                    'pid': parent.pid,
                    'name': parent.name(),
                    'exe': parent.exe() if hasattr(parent, 'exe') else 'N/A'
                })
                current = parent
            
            # Добавляем текущий процесс
            tree.append({
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe() if hasattr(proc, 'exe') else 'N/A'
            })
            
            # Получаем дочерние процессы
            for child in proc.children(recursive=True):
                tree.append({
                    'pid': child.pid,
                    'name': child.name(),
                    'exe': child.exe() if hasattr(child, 'exe') else 'N/A'
                })
            
            return tree
            
        except Exception as e:
            return []