# 🔍 Руководство по тестированию ADAR-Monitor

Это руководство поможет вам протестировать все функции системы мониторинга безопасности ADAR-Monitor и убедиться, что она правильно обнаруживает угрозы.

## 🚀 Быстрый старт

### Запуск программы

```bash
# Установка зависимостей
pip install -r requirements.txt

# Запуск с графическим интерфейсом (рекомендуется)
python3 main.py --gui

# Запуск в консольном режиме
python3 main.py --console
```

## 🧪 Тесты обнаружения отладчиков

### Тест 1: GDB (GNU Debugger)
```bash
# Установка GDB
sudo apt install gdb

# Запуск отладки программы
gdb /usr/bin/python3
(gdb) run /path/to/ADAR-Monitor/main.py --gui
```
**Ожидаемый результат:** Алерты "DEBUGGER" с уровнем КРИТИЧЕСКИЙ

### Тест 2: Strace (трассировка системных вызовов)
```bash
# Установка strace
sudo apt install strace

# Запуск трассировки работающей программы
strace -p $(pgrep -f "python.*main.py")
```
**Ожидаемый результат:** Алерты "PROCESS" для процесса strace

### Тест 3: Ltrace (трассировка библиотечных вызовов)
```bash
# Установка ltrace
sudo apt install ltrace

# Запуск с трассировкой
ltrace python3 main.py --console
```
**Ожидаемый результат:** Алерты "PROCESS" для процесса ltrace

## 🔍 Тесты мониторинга процессов

### Тест 4: Инструменты реверс-инжиниринга
```bash
# Установка инструментов
sudo apt install radare2 hexedit ghex binutils

# Тест с radare2
radare2 /bin/ls

# Тест с objdump
objdump -d /bin/ls

# Тест с hexdump
hexdump -C /bin/ls | head

# Тест с strings
strings /bin/ls
```
**Ожидаемый результат:** Алерты "PROCESS" с различными уровнями опасности

### Тест 5: Сетевые анализаторы
```bash
# Установка wireshark (только если необходимо)
sudo apt install wireshark

# Запуск tcpdump
sudo tcpdump -i any -c 10
```
**Ожидаемый результат:** Алерты "PROCESS" для сетевых анализаторов

## 🖥️ Тесты системного мониторинга

### Тест 6: Изменение критических файлов
```bash
# Тест изменения debug директории
sudo touch /sys/kernel/debug/test_file
sudo rm /sys/kernel/debug/test_file

# Тест записи в системные логи
sudo logger "Test security event from ADAR-Monitor"

# Тест изменения параметров ядра (осторожно!)
sudo sysctl -w kernel.dmesg_restrict=1
sudo sysctl -w kernel.dmesg_restrict=0
```
**Ожидаемый результат:** Алерты "SYSTEM" с уровнем СРЕДНИЙ

## 📊 Интерпретация результатов

### Уровни опасности алертов:

- **🔴 КРИТИЧЕСКИЙ** - Обнаружена активная попытка отладки или взлома
- **🟠 ВЫСОКИЙ** - Найдены подозрительные инструменты анализа
- **🟡 СРЕДНИЙ** - Изменения в системных файлах или обычные утилиты анализа
- **🟢 ИНФОРМАЦИЯ** - Обычные системные события

### Безопасные процессы (ложные срабатывания):

- `polkitd` - Управление привилегиями Ubuntu
- `systemd` - Системный менеджер
- `dbus` - Межпроцессное взаимодействие
- `NetworkManager` - Управление сетью

### Потенциально опасные процессы:

- `gdb`, `lldb` - Отладчики
- `strace`, `ltrace` - Трассировщики
- `radare2`, `ghidra` - Дизассемблеры
- `wireshark`, `tcpdump` - Анализаторы трафика
- `metasploit`, `nmap` - Инструменты пентестинга

## 🎯 Сценарии тестирования

### Сценарий 1: Имитация атаки
```bash
# Терминал 1: Запуск ADAR-Monitor
python3 main.py --gui

# Терминал 2: Имитация атаки
gdb /usr/bin/python3
(gdb) attach $(pgrep -f "python.*main.py")
```

### Сценарий 2: Анализ программы
```bash
# Терминал 1: Запуск ADAR-Monitor
python3 main.py --gui

# Терминал 2: Анализ бинарного файла
radare2 /bin/bash
[0x00000000]> aaa
[0x00000000]> pdf
```

### Сценарий 3: Системный анализ
```bash
# Терминал 1: Запуск ADAR-Monitor
python3 main.py --gui

# Терминал 2: Системный анализ
strace -e trace=file ls /tmp
sudo tcpdump -i lo -c 5
```

## 🔧 Настройка чувствительности

В файле конфигурации можно настроить:

- Интервалы проверки
- Список контролируемых процессов
- Пути к критическим файлам
- Уровни логирования

## ⚠️ Важные предупреждения

1. **Тестируйте только в безопасной среде** - не используйте реальные инструменты взлома на продакшн системах

2. **Некоторые тесты требуют sudo** - будьте осторожны с правами администратора

3. **Ложные срабатывания нормальны** - системные процессы могут вызывать алерты

4. **Мониторинг влияет на производительность** - учитывайте нагрузку на систему

## 🐛 Устранение неполадок

### Программа не запускается:
```bash
# Проверка зависимостей
pip install -r requirements.txt

# Проверка прав доступа
ls -la main.py
chmod +x main.py
```

### Нет алертов при тестировании:
```bash
# Проверка логов
python3 main.py --console

# Проверка процессов
ps aux | grep -E "(gdb|strace|radare2)"
```

### GUI не работает:
```bash
# Установка tkinter
sudo apt install python3-tk

# Запуск в консольном режиме
python3 main.py --console
```

## 📈 Анализ отчетов

После тестирования сохраните отчет через GUI и проанализируйте:

1. Количество обнаруженных угроз
2. Типы алертов и их частоту
3. Время отклика системы
4. Ложные срабатывания

## 🎓 Заключение

После успешного прохождения всех тестов вы можете быть уверены, что ADAR-Monitor правильно обнаруживает:

- ✅ Попытки отладки процессов
- ✅ Подозрительные инструменты анализа
- ✅ Изменения критических системных файлов
- ✅ Сетевую активность анализаторов

Теперь система готова к использованию для защиты ваших приложений от реверс-инжиниринга и отладки!