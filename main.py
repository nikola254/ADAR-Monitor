#!/usr/bin/env python3
"""
Утилита мониторинга защищённости системных приложений в Linux
Обнаружение отладки и реверс-инжиниринга
"""

import argparse
import sys
import os
import threading
import time
from pathlib import Path

# Добавляем src в путь для импортов
sys.path.append(str(Path(__file__).parent / 'src'))

from detectors.debugger_detector import DebuggerDetector
from detectors.process_monitor import ProcessMonitor
from monitoring.system_monitor import SystemMonitor
from gui.monitor_window import MonitorWindow

class SecurityMonitor:
    def __init__(self, gui_mode=False):
        self.gui_mode = gui_mode
        self.running = False
        
        # Инициализация детекторов
        self.debugger_detector = DebuggerDetector()
        self.process_monitor = ProcessMonitor()
        self.system_monitor = SystemMonitor()
        
        # GUI окно (если включен GUI режим)
        self.monitor_window = None
        
    def start_monitoring(self):
        """Запуск мониторинга"""
        self.running = True
        print("[INFO] Запуск мониторинга безопасности...")
        
        if self.gui_mode:
            self._start_gui_mode()
        else:
            self._start_console_mode()
    
    def _start_gui_mode(self):
        """Запуск в режиме с GUI"""
        try:
            from gui.monitor_window import MonitorWindow
            self.monitor_window = MonitorWindow(self)
            
            # Запуск мониторинга в отдельном потоке
            monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            monitor_thread.start()
            
            # Запуск GUI
            self.monitor_window.run()
        except ImportError:
            print("[ERROR] GUI библиотеки не установлены. Запуск в консольном режиме.")
            self._start_console_mode()
    
    def _start_console_mode(self):
        """Запуск в консольном режиме"""
        print("[INFO] Режим: Консоль")
        print("[INFO] Нажмите Ctrl+C для остановки")
        
        try:
            self._monitoring_loop()
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def _monitoring_loop(self):
        """Основной цикл мониторинга"""
        while self.running:
            try:
                # Проверка на отладчики
                if self.debugger_detector.check_debugger():
                    self._handle_threat("DEBUGGER", "Обнаружен отладчик!")
                
                # Мониторинг процессов
                suspicious_processes = self.process_monitor.scan_processes()
                if suspicious_processes:
                    for process in suspicious_processes:
                        self._handle_threat("PROCESS", f"Подозрительный процесс: {process}")
                
                # Системный мониторинг
                system_alerts = self.system_monitor.check_system()
                for alert in system_alerts:
                    self._handle_threat("SYSTEM", alert)
                
                time.sleep(1)  # Пауза между проверками
                
            except Exception as e:
                print(f"[ERROR] Ошибка в цикле мониторинга: {e}")
                time.sleep(5)
    
    def _handle_threat(self, threat_type, message):
        """Обработка обнаруженной угрозы"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] [{threat_type}] {message}"
        
        print(alert_msg)
        
        # Если GUI активен, отправляем уведомление в окно
        if self.monitor_window:
            self.monitor_window.add_alert(threat_type, message, timestamp)
    
    def stop_monitoring(self):
        """Остановка мониторинга"""
        self.running = False
        print("\n[INFO] Мониторинг остановлен")
        
        if self.monitor_window:
            self.monitor_window.close()

def main():
    parser = argparse.ArgumentParser(
        description="Утилита мониторинга защищённости системных приложений"
    )
    
    parser.add_argument(
        "--gui", 
        action="store_true", 
        help="Запуск с графическим интерфейсом"
    )
    
    parser.add_argument(
        "--console", 
        action="store_true", 
        help="Запуск в консольном режиме (по умолчанию)"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version="Security Monitor v1.0"
    )
    
    args = parser.parse_args()
    
    # Проверка ОС
    if os.name != 'posix':
        print("[WARNING] Утилита предназначена для Linux систем")
    
    # Определение режима запуска
    gui_mode = args.gui or not args.console
    
    # Создание и запуск монитора
    monitor = SecurityMonitor(gui_mode=gui_mode)
    monitor.start_monitoring()

if __name__ == "__main__":
    main()