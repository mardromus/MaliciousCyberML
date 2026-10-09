@echo off
rem Installs the Python libraries the project needs (run once).
cd /d "%~dp0"
python --version || (echo Python 3.10 or newer is required: https://www.python.org/downloads/ & pause & exit /b 1)
python -m pip install -r requirements.txt
pause
