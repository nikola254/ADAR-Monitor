#!/bin/bash
# Security Monitor Launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Активация виртуального окружения если существует
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Запуск приложения
python3 main.py "$@"
