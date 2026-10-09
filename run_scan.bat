@echo off
rem Scores PowerShell scripts with the saved model and shows the automated response (dry run).
rem Double-click to scan the examples, or drag .ps1/.txt files onto this file to scan them.
cd /d "%~dp0"
if "%~1"=="" (python demo\scan.py examples\benign_admin.txt examples\download_cradle.txt examples\injection_loader.txt) else (python demo\scan.py %*)
pause
