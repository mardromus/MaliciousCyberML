@echo off
rem Reproduces every number and figure in the report from the MPSD dataset (takes 30+ minutes).
cd /d "%~dp0"
if not exist data\mpsd\malicious_pure (git clone --depth 1 https://github.com/das-lab/mpsd data\mpsd || (echo Could not download the dataset. See README.md. & pause & exit /b 1))
python experiments\run_experiments.py --data data\mpsd
python experiments\mixed_training.py --data data\mpsd
python experiments\simulate_response.py --data data\mpsd
python experiments\error_analysis.py --data data\mpsd
python experiments\make_figures.py
python demo\train_model.py --data data\mpsd
pause
