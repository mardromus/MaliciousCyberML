@echo off
rem Downloads the public MPSD dataset (needs git), then cleans it, trains and evaluates the
rem ensemble and runs the response engine. About 2 minutes.
cd /d "%~dp0"
if not exist data\mpsd\malicious_pure (git clone --depth 1 https://github.com/das-lab/mpsd data\mpsd || (echo Could not download the dataset. See README.md. & pause & exit /b 1))
python demo\demo_pipeline.py --data data\mpsd
pause
