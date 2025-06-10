#!/usr/bin/env python3
"""
Системный монитор для отслеживания подозрительной активности
"""

import os
import time
import psutil
import socket
from pathlib import Path

class SystemMonitor:
    def __init__(self):
        self.last_check_time = 0
        self.check_interval = 3.0  # Интервал проверки в секундах
        
        # Критичные файлы и директории для мониторинга
        self.critical_paths = {
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/root/.ssh/',
            '/home/*/.ssh/',
            '/var/log/auth.log',
            '/var/log/secure',
            '/proc/sys/kernel/',
            '/sys/kernel/debug/'
        }
        
        # Подозрительные сетевые порты
        self.suspicious_ports = {
            4444,   # Metasploit default
            4445,   # Metasploit
            5555,   # Android Debug Bridge
            6666,   # IRC/Backdoor
            7777,   # Backdoor
            8080,   # HTTP Proxy
            9999,   # Backdoor
            31337,  # Elite/Backdoor
            12345,  # NetBus
            54321   # Back Orifice
        }
        
        # Базовые показатели системы
        self.baseline_cpu = None
        self.baseline_memory = None
        self.baseline_network = None
        
        self._establish_baseline()
    
    def check_system(self):
        """Основная функция проверки системы"""
        current_time = time.time()
        if current_time - self.last_check_time < self.check_interval:
            return []
        
        self.last_check_time = current_time
        alerts = []
        
        # Проверка различных аспектов системы
        alerts.extend(self._check_file_access())
        alerts.extend(self._check_network_activity())
        alerts.extend(self._check_system_resources())
        alerts.extend(self._check_kernel_modules())
        alerts.extend(self._check_environment())
        
        return alerts
    
    def _establish_baseline(self):
        """Установка базовых показателей системы"""
        try:
            self.baseline_cpu = psutil.cpu_percent(interval=1)
            self.baseline_memory = psutil.virtual_memory().percent
            self.baseline_network = psutil.net_io_counters()
        except Exception:
            pass
    
    def _check_file_access(self):
        """Проверка доступа к критичным файлам"""
        alerts = []
        
        try:
            # Проверка времени модификации критичных файлов
            for path_pattern in self.critical_paths:
                if '*' in path_pattern:
                    # Обработка паттернов с wildcards
                    continue
                
                if os.path.exists(path_pattern):
                    stat_info = os.stat(path_pattern)
                    
                    # Проверка недавних изменений (последние 5 минут)
                    if time.time() - stat_info.st_mtime < 300:
                        alerts.append(f"Недавнее изменение критичного файла: {path_pattern}")
                    
                    # Проверка подозрительных прав доступа
                    mode = stat_info.st_mode
                    if mode & 0o002:  # World writable
                        alerts.append(f"Критичный файл доступен для записи всем: {path_pattern}")
        
        except Exception as e:
            alerts.append(f"Ошибка при проверке файлов: {e}")
        
        return alerts
    
    def _check_network_activity(self):
        """Проверка сетевой активности"""
        alerts = []
        
        try:
            # Проверка открытых портов
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    port = conn.laddr.port
                    
                    # Проверка подозрительных портов
                    if port in self.suspicious_ports:
                        alerts.append(f"Подозрительный открытый порт: {port}")
                    
                    # Проверка портов с высокими номерами
                    if port > 49152:  # Dynamic/Private ports
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            proc_name = proc.name() if proc else "Unknown"
                            alerts.append(f"Высокий порт {port} открыт процессом: {proc_name}")
                        except Exception:
                            pass
            
            # Проверка необычного сетевого трафика
            current_net = psutil.net_io_counters()
            if self.baseline_network:
                bytes_sent_diff = current_net.bytes_sent - self.baseline_network.bytes_sent
                bytes_recv_diff = current_net.bytes_recv - self.baseline_network.bytes_recv
                
                # Пороговые значения для подозрительного трафика (в байтах)
                if bytes_sent_diff > 10 * 1024 * 1024:  # 10 MB
                    alerts.append(f"Высокий исходящий трафик: {bytes_sent_diff / 1024 / 1024:.2f} MB")
                
                if bytes_recv_diff > 50 * 1024 * 1024:  # 50 MB
                    alerts.append(f"Высокий входящий трафик: {bytes_recv_diff / 1024 / 1024:.2f} MB")
        
        except Exception as e:
            alerts.append(f"Ошибка при проверке сети: {e}")
        
        return alerts
    
    def _check_system_resources(self):
        """Проверка использования системных ресурсов"""
        alerts = []
        
        try:
            # Проверка CPU
            current_cpu = psutil.cpu_percent(interval=0.1)
            if current_cpu > 90:
                alerts.append(f"Высокая загрузка CPU: {current_cpu}%")
            
            # Проверка памяти
            memory = psutil.virtual_memory()
            if memory.percent > 95:
                alerts.append(f"Высокое использование памяти: {memory.percent}%")
            
            # Проверка дискового пространства
            disk = psutil.disk_usage('/')
            if disk.percent > 95:
                alerts.append(f"Мало места на диске: {disk.percent}% использовано")
            
            # Проверка количества процессов
            process_count = len(psutil.pids())
            if process_count > 500:
                alerts.append(f"Большое количество процессов: {process_count}")
        
        except Exception as e:
            alerts.append(f"Ошибка при проверке ресурсов: {e}")
        
        return alerts
    
    def _check_kernel_modules(self):
        """Проверка загруженных модулей ядра"""
        alerts = []
        
        try:
            # Подозрительные модули ядра
            suspicious_modules = {
                'rootkit', 'keylogger', 'backdoor',
                'stealth', 'hidden', 'invisible'
            }
            
            # Чтение списка загруженных модулей
            if os.path.exists('/proc/modules'):
                with open('/proc/modules', 'r') as f:
                    modules = f.read().lower()
                    
                    for suspicious in suspicious_modules:
                        if suspicious in modules:
                            alerts.append(f"Подозрительный модуль ядра: {suspicious}")
        
        except Exception as e:
            alerts.append(f"Ошибка при проверке модулей ядра: {e}")
        
        return alerts
    
    def _check_environment(self):
        """Проверка переменных окружения и системных настроек"""
        alerts = []
        
        try:
            # Проверка подозрительных переменных окружения
            suspicious_env_vars = {
                'LD_PRELOAD',    # Может использоваться для инъекций
                'LD_LIBRARY_PATH',
                'DYLD_INSERT_LIBRARIES',  # macOS equivalent
                'PTRACE_SCOPE'
            }
            
            for var in suspicious_env_vars:
                if var in os.environ:
                    value = os.environ[var]
                    if value:
                        alerts.append(f"Подозрительная переменная окружения {var}: {value}")
            
            # Проверка настроек ptrace
            ptrace_scope_file = '/proc/sys/kernel/yama/ptrace_scope'
            if os.path.exists(ptrace_scope_file):
                with open(ptrace_scope_file, 'r') as f:
                    ptrace_scope = f.read().strip()
                    if ptrace_scope == '0':
                        alerts.append("ptrace_scope установлен в 0 - отладка разрешена")
        
        except Exception as e:
            alerts.append(f"Ошибка при проверке окружения: {e}")
        
        return alerts
    
    def get_system_info(self):
        """Получение общей информации о системе"""
        info = {}
        
        try:
            info['cpu_percent'] = psutil.cpu_percent(interval=1)
            info['memory_percent'] = psutil.virtual_memory().percent
            info['disk_percent'] = psutil.disk_usage('/').percent
            info['process_count'] = len(psutil.pids())
            info['network_connections'] = len(psutil.net_connections())
            info['boot_time'] = psutil.boot_time()
        except Exception as e:
            info['error'] = str(e)
        
        return info