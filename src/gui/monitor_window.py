#!/usr/bin/env python3
"""
Графический интерфейс для мониторинга безопасности
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
from datetime import datetime

class MonitorWindow:
    def __init__(self, security_monitor):
        self.security_monitor = security_monitor
        self.root = tk.Tk()
        self.running = True
        
        # Настройка главного окна
        self.root.title("Security Monitor - Мониторинг безопасности")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Создание интерфейса
        self.create_widgets()
        
        # Запуск обновления GUI
        self.update_gui()
    
    def create_widgets(self):
        """Создание элементов интерфейса"""
        # Главный фрейм
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Настройка растягивания
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Заголовок
        title_label = ttk.Label(main_frame, text="Мониторинг безопасности системы", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Статус мониторинга
        status_frame = ttk.LabelFrame(main_frame, text="Статус", padding="5")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Состояние:").grid(row=0, column=0, sticky=tk.W)
        self.status_label = ttk.Label(status_frame, text="Запущен", foreground="green")
        self.status_label.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(status_frame, text="Время работы:").grid(row=1, column=0, sticky=tk.W)
        self.uptime_label = ttk.Label(status_frame, text="00:00:00")
        self.uptime_label.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(status_frame, text="Обнаружено угроз:").grid(row=2, column=0, sticky=tk.W)
        self.threats_label = ttk.Label(status_frame, text="0", foreground="red")
        self.threats_label.grid(row=2, column=1, sticky=tk.W)
        
        # Создание notebook для вкладок
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Вкладка "Алерты"
        alerts_frame = ttk.Frame(notebook)
        notebook.add(alerts_frame, text="Алерты")
        
        # Текстовое поле для алертов
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=15, width=70)
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка "Системная информация"
        sysinfo_frame = ttk.Frame(notebook)
        notebook.add(sysinfo_frame, text="Система")
        
        # Информация о системе
        self.sysinfo_text = scrolledtext.ScrolledText(sysinfo_frame, height=15, width=70)
        self.sysinfo_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка "Процессы"
        processes_frame = ttk.Frame(notebook)
        notebook.add(processes_frame, text="Процессы")
        
        # Список подозрительных процессов
        self.processes_text = scrolledtext.ScrolledText(processes_frame, height=15, width=70)
        self.processes_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка "Тестирование"
        testing_frame = ttk.Frame(notebook)
        notebook.add(testing_frame, text="Тестирование")
        
        # Инструкции по тестированию
        testing_text = scrolledtext.ScrolledText(testing_frame, height=15, width=70, wrap=tk.WORD)
        testing_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Заполняем инструкции по тестированию
        testing_instructions = """=== ИНСТРУКЦИИ ПО ТЕСТИРОВАНИЮ ADAR-Monitor ===

🔍 КАК ПРОТЕСТИРОВАТЬ ОБНАРУЖЕНИЕ ОТЛАДЧИКОВ:

1. Тест с GDB (GNU Debugger):
   sudo apt install gdb
   gdb /usr/bin/python3
   (gdb) run /path/to/your/main.py --gui
   → Должны появиться алерты "DEBUGGER" с уровнем КРИТИЧЕСКИЙ

2. Тест с Strace (системные вызовы):
   sudo apt install strace
   strace -p $(pgrep -f "python.*main.py")
   → Должны появиться алерты "PROCESS" для strace

3. Тест с ltrace (библиотечные вызовы):
   sudo apt install ltrace
   ltrace python3 main.py --console
   → Должны появиться алерты "PROCESS" для ltrace

🔍 КАК ПРОТЕСТИРОВАТЬ МОНИТОРИНГ ПРОЦЕССОВ:

1. Установите инструменты реверс-инжиниринга:
   sudo apt install radare2 hexedit ghex
   
2. Запустите любой из них:
   radare2 /bin/ls
   → Должен появиться алерт "PROCESS" с уровнем ВЫСОКИЙ

3. Другие инструменты для тестирования:
   - objdump -d /bin/ls
   - hexdump -C /bin/ls
   - strings /bin/ls

🔍 КАК ПРОТЕСТИРОВАТЬ СИСТЕМНЫЙ МОНИТОРИНГ:

1. Изменение критических файлов:
   sudo touch /sys/kernel/debug/test_file
   sudo rm /sys/kernel/debug/test_file
   → Должны появиться алерты "SYSTEM" с уровнем СРЕДНИЙ

2. Мониторинг логов аутентификации:
   sudo logger "Test security event"
   → Может вызвать алерт "SYSTEM"

🔍 БЕЗОПАСНЫЕ VS ОПАСНЫЕ ПРОЦЕССЫ:

✅ БЕЗОПАСНЫЕ (обычно ложные срабатывания):
   - polkitd - управление привилегиями Ubuntu
   - systemd - системный менеджер
   - dbus - межпроцессное взаимодействие
   - NetworkManager - управление сетью

❌ ПОТЕНЦИАЛЬНО ОПАСНЫЕ:
   - gdb, lldb - отладчики
   - strace, ltrace - трассировщики
   - radare2, ghidra - дизассемблеры
   - wireshark - анализатор сетевого трафика
   - metasploit - фреймворк для тестирования на проникновение

🔍 РЕКОМЕНДАЦИИ ПО ТЕСТИРОВАНИЮ:

1. Запустите программу в GUI режиме:
   python3 main.py --gui

2. Откройте вкладку "Алерты" для мониторинга

3. В отдельном терминале запускайте тестовые команды

4. Наблюдайте за появлением алертов с пояснениями

5. Проверьте вкладки "Система" и "Процессы" для дополнительной информации

⚠️ ВАЖНО: Тестирование с реальными инструментами взлома может быть опасно. Используйте только в изолированной среде!"""
        
        testing_text.insert(1.0, testing_instructions)
        testing_text.config(state=tk.DISABLED)  # Делаем текст только для чтения
        
        # Кнопки управления
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        self.pause_button = ttk.Button(buttons_frame, text="Пауза", command=self.toggle_monitoring)
        self.pause_button.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(buttons_frame, text="Очистить логи", command=self.clear_logs).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="Сохранить отчёт", command=self.save_report).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(buttons_frame, text="Выход", command=self.on_closing).pack(side=tk.RIGHT)
        
        # Инициализация данных
        self.start_time = time.time()
        self.threat_count = 0
        self.monitoring_paused = False
        
        # Добавляем начальное сообщение
        self.add_alert("INFO", "Мониторинг безопасности запущен", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def add_alert(self, alert_type, message, timestamp):
        """Добавление нового алерта с подробными пояснениями"""
        if not self.running:
            return
        
        # Определение цвета и уровня опасности по типу алерта
        alert_info = {
            "DEBUGGER": {
                "color": "red",
                "level": "КРИТИЧЕСКИЙ",
                "description": "Обнаружена попытка отладки процесса",
                "recommendation": "Немедленно проверьте систему на наличие вредоносного ПО"
            },
            "PROCESS": {
                "color": "orange",
                "level": "ВЫСОКИЙ",
                "description": "Найден подозрительный процесс",
                "recommendation": "Проверьте процесс в списке разрешенных программ"
            },
            "SYSTEM": {
                "color": "blue",
                "level": "СРЕДНИЙ",
                "description": "Изменения в критических системных файлах",
                "recommendation": "Проверьте журналы системы на предмет несанкционированных изменений"
            },
            "INFO": {
                "color": "green",
                "level": "ИНФОРМАЦИЯ",
                "description": "Информационное сообщение",
                "recommendation": "Действий не требуется"
            },
            "WARNING": {
                "color": "orange",
                "level": "ПРЕДУПРЕЖДЕНИЕ",
                "description": "Потенциальная проблема безопасности",
                "recommendation": "Рекомендуется дополнительная проверка"
            },
            "ERROR": {
                "color": "red",
                "level": "ОШИБКА",
                "description": "Ошибка в работе системы мониторинга",
                "recommendation": "Проверьте настройки и перезапустите мониторинг"
            }
        }
        
        info = alert_info.get(alert_type, {
            "color": "black",
            "level": "НЕИЗВЕСТНО",
            "description": "Неизвестный тип события",
            "recommendation": "Обратитесь к документации"
        })
        
        # Расширенное форматирование сообщения с пояснениями
        if alert_type in ["DEBUGGER", "PROCESS", "SYSTEM", "WARNING", "ERROR"]:
            formatted_message = f"[{timestamp}] [{alert_type}] {message}\n"
            formatted_message += f"    ├─ Уровень опасности: {info['level']}\n"
            formatted_message += f"    ├─ Описание: {info['description']}\n"
            formatted_message += f"    └─ Рекомендация: {info['recommendation']}\n\n"
        else:
            formatted_message = f"[{timestamp}] [{alert_type}] {message}\n"
        
        # Добавление в текстовое поле
        self.alerts_text.insert(tk.END, formatted_message)
        
        # Настройка цвета для блока сообщения
        if alert_type in ["DEBUGGER", "PROCESS", "SYSTEM", "WARNING", "ERROR"]:
            # Выделяем весь блок (основное сообщение + пояснения)
            lines_count = 4  # основная строка + 3 строки пояснений + пустая строка
            for i in range(lines_count):
                line_start = self.alerts_text.index(f"end-{lines_count-i+1}c linestart")
                line_end = self.alerts_text.index(f"end-{lines_count-i}c")
                
                tag_name = f"alert_{alert_type}_{time.time()}_{i}"
                self.alerts_text.tag_add(tag_name, line_start, line_end)
                
                if i == 0:  # Основная строка
                    self.alerts_text.tag_config(tag_name, foreground=info['color'], font=('Arial', 9, 'bold'))
                else:  # Строки пояснений
                    self.alerts_text.tag_config(tag_name, foreground='gray', font=('Arial', 8))
        else:
            # Обычное форматирование для INFO
            line_start = self.alerts_text.index("end-2c linestart")
            line_end = self.alerts_text.index("end-1c")
            
            tag_name = f"alert_{alert_type}_{time.time()}"
            self.alerts_text.tag_add(tag_name, line_start, line_end)
            self.alerts_text.tag_config(tag_name, foreground=info['color'])
        
        # Автопрокрутка
        self.alerts_text.see(tk.END)
        
        # Увеличение счётчика угроз
        if alert_type in ["DEBUGGER", "PROCESS", "SYSTEM"]:
            self.threat_count += 1
            self.threats_label.config(text=str(self.threat_count))
    
    def update_gui(self):
        """Обновление GUI каждую секунду"""
        if not self.running:
            return
        
        # Обновление времени работы
        uptime = time.time() - self.start_time
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        seconds = int(uptime % 60)
        self.uptime_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        # Обновление системной информации
        self.update_system_info()
        
        # Обновление списка процессов
        self.update_processes_info()
        
        # Планирование следующего обновления
        self.root.after(1000, self.update_gui)
    
    def update_system_info(self):
        """Обновление информации о системе"""
        try:
            if hasattr(self.security_monitor, 'system_monitor'):
                info = self.security_monitor.system_monitor.get_system_info()
                
                info_text = "=== СИСТЕМНАЯ ИНФОРМАЦИЯ ===\n\n"
                info_text += f"CPU: {info.get('cpu_percent', 'N/A')}%\n"
                info_text += f"Память: {info.get('memory_percent', 'N/A')}%\n"
                info_text += f"Диск: {info.get('disk_percent', 'N/A')}%\n"
                info_text += f"Процессы: {info.get('process_count', 'N/A')}\n"
                info_text += f"Сетевые соединения: {info.get('network_connections', 'N/A')}\n"
                
                if 'boot_time' in info:
                    boot_time = datetime.fromtimestamp(info['boot_time'])
                    info_text += f"Время загрузки: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                
                # Обновляем текст
                self.sysinfo_text.delete(1.0, tk.END)
                self.sysinfo_text.insert(1.0, info_text)
        
        except Exception as e:
            pass
    
    def update_processes_info(self):
        """Обновление информации о процессах с пояснениями"""
        try:
            if hasattr(self.security_monitor, 'process_monitor'):
                processes = self.security_monitor.process_monitor.get_all_suspicious_processes()
                
                processes_text = "=== ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ===\n\n"
                
                # Словарь с описаниями процессов
                process_descriptions = {
                    'gdb': '🔴 КРИТИЧЕСКИЙ - Отладчик GNU, используется для анализа программ',
                    'lldb': '🔴 КРИТИЧЕСКИЙ - Отладчик LLVM, может использоваться для взлома',
                    'strace': '🟠 ВЫСОКИЙ - Трассировщик системных вызовов',
                    'ltrace': '🟠 ВЫСОКИЙ - Трассировщик библиотечных вызовов',
                    'radare2': '🔴 КРИТИЧЕСКИЙ - Мощный дизассемблер и отладчик',
                    'ghidra': '🔴 КРИТИЧЕСКИЙ - Инструмент реверс-инжиниринга NSA',
                    'ida': '🔴 КРИТИЧЕСКИЙ - Профессиональный дизассемблер IDA Pro',
                    'objdump': '🟡 СРЕДНИЙ - Утилита для анализа объектных файлов',
                    'hexdump': '🟡 СРЕДНИЙ - Просмотр файлов в шестнадцатеричном формате',
                    'strings': '🟡 СРЕДНИЙ - Извлечение строк из бинарных файлов',
                    'wireshark': '🟠 ВЫСОКИЙ - Анализатор сетевого трафика',
                    'tcpdump': '🟠 ВЫСОКИЙ - Перехватчик сетевых пакетов',
                    'metasploit': '🔴 КРИТИЧЕСКИЙ - Фреймворк для тестирования на проникновение',
                    'nmap': '🟠 ВЫСОКИЙ - Сканер портов и сетевой разведки',
                    'polkitd': '🟢 БЕЗОПАСНЫЙ - Системный процесс управления привилегиями Ubuntu',
                    'systemd': '🟢 БЕЗОПАСНЫЙ - Системный менеджер инициализации',
                    'dbus': '🟢 БЕЗОПАСНЫЙ - Система межпроцессного взаимодействия',
                    'NetworkManager': '🟢 БЕЗОПАСНЫЙ - Менеджер сетевых подключений'
                }
                
                if processes:
                    for i, process in enumerate(processes, 1):
                        process_name = process.split()[0] if process else 'unknown'
                        description = process_descriptions.get(process_name, '🟡 НЕИЗВЕСТНЫЙ - Требует дополнительной проверки')
                        
                        processes_text += f"{i}. {process}\n"
                        processes_text += f"   └─ {description}\n\n"
                else:
                    processes_text += "✅ Подозрительные процессы не обнаружены\n\n"
                    processes_text += "Это означает, что в системе не найдены известные инструменты\n"
                    processes_text += "для отладки, реверс-инжиниринга или анализа безопасности.\n\n"
                
                processes_text += "=== ЛЕГЕНДА УРОВНЕЙ ОПАСНОСТИ ===\n\n"
                processes_text += "🔴 КРИТИЧЕСКИЙ - Немедленно требует внимания\n"
                processes_text += "🟠 ВЫСОКИЙ - Потенциально опасный процесс\n"
                processes_text += "🟡 СРЕДНИЙ - Может использоваться для анализа\n"
                processes_text += "🟢 БЕЗОПАСНЫЙ - Обычный системный процесс\n"
                
                # Обновляем текст
                self.processes_text.delete(1.0, tk.END)
                self.processes_text.insert(1.0, processes_text)
        
        except Exception as e:
            pass
    
    def toggle_monitoring(self):
        """Переключение паузы мониторинга"""
        self.monitoring_paused = not self.monitoring_paused
        
        if self.monitoring_paused:
            self.pause_button.config(text="Возобновить")
            self.status_label.config(text="Приостановлен", foreground="orange")
            self.security_monitor.running = False
        else:
            self.pause_button.config(text="Пауза")
            self.status_label.config(text="Запущен", foreground="green")
            self.security_monitor.running = True
            
            # Перезапуск мониторинга в отдельном потоке
            monitor_thread = threading.Thread(target=self.security_monitor._monitoring_loop, daemon=True)
            monitor_thread.start()
    
    def clear_logs(self):
        """Очистка логов"""
        self.alerts_text.delete(1.0, tk.END)
        self.threat_count = 0
        self.threats_label.config(text="0")
        self.add_alert("INFO", "Логи очищены", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def save_report(self):
        """Сохранение отчёта"""
        try:
            from tkinter import filedialog
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Сохранить отчёт"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("=== ОТЧЁТ МОНИТОРИНГА БЕЗОПАСНОСТИ ===\n\n")
                    f.write(f"Время создания: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Обнаружено угроз: {self.threat_count}\n\n")
                    f.write("=== АЛЕРТЫ ===\n")
                    f.write(self.alerts_text.get(1.0, tk.END))
                    f.write("\n=== СИСТЕМНАЯ ИНФОРМАЦИЯ ===\n")
                    f.write(self.sysinfo_text.get(1.0, tk.END))
                    f.write("\n=== ПРОЦЕССЫ ===\n")
                    f.write(self.processes_text.get(1.0, tk.END))
                
                messagebox.showinfo("Успех", f"Отчёт сохранён: {filename}")
        
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчёт: {e}")
    
    def on_closing(self):
        """Обработка закрытия окна"""
        if messagebox.askokcancel("Выход", "Вы уверены, что хотите выйти?"):
            self.running = False
            self.security_monitor.running = False
            self.root.destroy()
    
    def close(self):
        """Закрытие окна"""
        self.running = False
        if self.root:
            self.root.quit()
    
    def run(self):
        """Запуск GUI"""
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"[ERROR] Ошибка GUI: {e}")