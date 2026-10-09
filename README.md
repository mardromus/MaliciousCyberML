# AI-Powered Detection and Automated Response to Malicious PowerShell Attacks Using Machine Learning

Cyber Security case study (Unit 4) · **Group G53** · Kushagra (23070122122) ·
Submitted to Dr. Pooja Bagane, Department of CSE, Symbiosis Institute of Technology, Pune

**GitHub:** https://github.com/mardromus/MaliciousCyberML

The system reads PowerShell script text (as Windows logs it in Event ID 4104),
scores how likely it is to be malicious with a machine-learning ensemble, maps
what it finds to MITRE ATT&CK techniques, and picks an automated response:
ALLOW, ALERT, CONTAIN or ISOLATE (isolation always waits for an analyst).
Responses run in dry-run mode: they are logged, never carried out.

---

## 1. Quick start on Windows (about 5 minutes, no dataset needed)

1. Install **Python 3.10 or newer** from https://www.python.org/downloads/
   and tick **"Add python.exe to PATH"** during setup.
2. Unzip this folder anywhere, for example to the Desktop.
3. Double-click the launchers in this order:

| Launcher | What it does | Time |
| --- | --- | --- |
| `setup.bat` | Installs the Python libraries from `requirements.txt` (run once) | 1–3 min |
| `run_tests.bat` | Runs the 7 unit tests; all should show PASSED | seconds |
| `run_scan.bat` | Scores the three example scripts in `examples/` with the saved model and prints each response decision. Drag your own `.ps1` or `.txt` files onto it to scan them | seconds |
| `run_full_demo.bat` | Downloads the MPSD dataset, cleans it, trains and evaluates the ensemble, then runs the response engine (needs `git` and internet) | ~2 min |
| `run_experiments.bat` | Reproduces every number and figure in the report | 30+ min |

Expected output of `run_scan.bat`: the benign admin script is **ALLOW**ed, the
download cradle is **CONTAIN**ed with T1105 and its address shown in safe
`hxxp://203[.]0[.]113[.]5` form, and the injection-style loader raises an
**ALERT** with T1027, T1620 and T1055.

## 2. Running from a terminal (Windows, macOS or Linux)

```bash
pip install -r requirements.txt                      # once

python demo/run_tests.py                             # unit tests (or: python -m pytest -v tests)
python demo/scan.py examples/*.txt                   # score scripts with the saved model

git clone --depth 1 https://github.com/das-lab/mpsd data/mpsd     # public MPSD dataset
python demo/demo_pipeline.py --data data/mpsd        # clean, train, evaluate, respond (~2 min)
python demo/train_model.py --data data/mpsd          # retrain models/ensemble.joblib

# full reproduction of the report (30+ min)
python experiments/run_experiments.py --data data/mpsd
python experiments/mixed_training.py --data data/mpsd
python experiments/simulate_response.py --data data/mpsd
python experiments/error_analysis.py --data data/mpsd
python experiments/make_figures.py
```

On Linux or macOS, `scripts/get_data.sh data/mpsd` also downloads the dataset.

## 3. What is in this folder

| Path | Contents |
| --- | --- |
| `src/psdetect/data.py` | Loads MPSD, strips byte-order marks, removes exact duplicates and label conflicts, groups near-duplicates by a structural "skeleton" hash |
| `src/psdetect/features.py` | Case and backtick normalisation, 24 statistical features, 9 ATT&CK-aligned behavioural indicator groups |
| `src/psdetect/models.py` | Char 3–5-gram TF-IDF + Logistic Regression; hand-crafted features + LR / Random Forest / HistGradientBoosting; soft-voting ensemble |
| `src/psdetect/response.py` | Tiered response engine for Event ID 4104 records: ATT&CK mapping, defanged IOCs, dry-run actions, JSONL audit log |
| `demo/` | `scan.py` (score files with the saved model), `demo_pipeline.py` (end-to-end demo), `train_model.py` (rebuild the saved model), `run_tests.py` (tests without pytest) |
| `models/ensemble.joblib` | Saved ensemble trained on the full cleaned dataset (scikit-learn 1.9.1) |
| `examples/` | Three inert sample scripts as text for `scan.py` |
| `experiments/` | Scripts that produce every number and figure in the report |
| `results/` | Metrics (`metrics.json`, `response_summary.json`, `mixed_training.json`), out-of-fold scores and figures |
| `tests/` | Unit tests |
| `report/` | Final report `G_53.pdf`, LaTeX source `main.tex`, Word version, logo |
| `presentation/screenshots/` | Screenshots of the implementation used in the video presentation |
| `*.bat` | Windows launchers (section 1) |

## 4. Key results (from the report)

| Measure | Value |
| --- | --- |
| Dataset after cleaning | 1,875 malicious + 4,302 benign scripts (55.2% of malicious files were duplicates) |
| Ensemble F1 / precision / recall (5-fold, family-aware) | 0.972 / 0.984 / 0.962 |
| False-positive rate | 0.7% (30 of 4,302 benign scripts) |
| Malicious code hidden in normal scripts | 46.7% detected, 96.4% after training with mixed examples |
| Response test on 1,233 unseen scripts | 91.2% of malicious contained, 0.23% of benign wrongly blocked, median 90.7 ms per script |

## 5. Troubleshooting

- **`python` is not recognised**: reinstall Python with "Add python.exe to PATH" ticked, or use `py` instead of `python`.
- **"Could not load the saved model"**: the model was saved with scikit-learn 1.9.1. Run `pip install scikit-learn==1.9.1`, or download the dataset and run `python demo/train_model.py --data data/mpsd`.
- **Antivirus warnings on `data/mpsd`**: the MPSD dataset contains real malicious PowerShell scripts as text, so antivirus software may flag or quarantine them. The project only reads them as text and never runs them. The quick start in section 1 does not need the dataset.
- **`git` is not installed**: download the dataset as a ZIP from https://github.com/das-lab/mpsd and extract it to `data/mpsd`, so that `data/mpsd/malicious_pure` exists.

## 6. Safety notes

Scripts are handled only as text and are never executed. The dataset is
downloaded from its public source and is not included in this package. The
response engine runs in dry-run mode, and host isolation always requires
analyst approval.

## 7. Dataset and reference

Y. Fang, X. Zhou and C. Huang, "Effective method for detecting malicious
PowerShell scripts based on hybrid features," *Neurocomputing* 448:30–39, 2021.
https://github.com/das-lab/mpsd
