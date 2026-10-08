# AI-Powered Detection and Automated Response to Malicious PowerShell Attacks

Cyber Security case study (Unit 4). The repository holds:

- `src/psdetect/` — the detection and response package
  - `data.py`: loads MPSD, strips byte-order marks, removes exact duplicates and label conflicts, groups near-duplicates by a structural "skeleton" hash
  - `features.py`: case/backtick normalisation, 24 statistical features, 9 ATT&CK-aligned behavioural indicator groups
  - `models.py`: char 3–5-gram TF-IDF + Logistic Regression, hand-crafted + LR / Random Forest / HistGradientBoosting, soft-voting ensemble
  - `response.py`: tiered response engine (ALLOW / ALERT / CONTAIN / ISOLATE) for Event ID 4104 records, with ATT&CK mapping, defanged IOCs, dry-run actions and a JSONL audit log
- `experiments/` — scripts that produce every number and figure in the report
- `results/` — metrics (`metrics.json`, `response_summary.json`), out-of-fold scores and figures
- `report/main.tex` — the case study report as a single LaTeX file for Overleaf (figures drawn in LaTeX, references included); `report/main.pdf` is the compiled version
- `tests/` — unit tests

## Reproduce

```bash
pip install -r requirements.txt
scripts/get_data.sh data/mpsd                 # public MPSD corpus (not committed)
python experiments/run_experiments.py --data data/mpsd
python experiments/mixed_training.py --data data/mpsd
python experiments/simulate_response.py --data data/mpsd
python experiments/error_analysis.py --data data/mpsd
python experiments/make_figures.py
python -m pytest -q tests
```

### Report on Overleaf

Create a blank Overleaf project, replace its `main.tex` with `report/main.tex`
and compile with pdfLaTeX (the default). No other files are required. Before
submitting, fill in the group number, member names, roll numbers, faculty,
department and institute in the title-page block near the top of `main.tex`,
recompile, and download the PDF named after your group number, e.g. `G10.pdf`.

```bash
# local build (TeX Live)
latexmk -pdf -outdir=report report/main.tex
```

## Safety notes

Malicious samples are handled only as text and are never executed. The dataset
is fetched from its public source and is not stored in this repository. The
response engine runs in dry-run mode by default, and host isolation always
requires analyst approval.

## Dataset

Y. Fang, X. Zhou and C. Huang, "Effective method for detecting malicious
PowerShell scripts based on hybrid features," *Neurocomputing* 448:30–39, 2021.
https://github.com/das-lab/mpsd
