@echo off
rem Runs the seven unit tests (no dataset needed).
cd /d "%~dp0"
python demo\run_tests.py
pause
