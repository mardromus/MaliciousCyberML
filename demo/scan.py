"""Scores PowerShell script files with the saved model and prints the automated
response decision for each (dry run: nothing is executed or changed).
Usage:  python demo/scan.py examples/*.txt      (any .ps1 / .txt files)
The files are read only as text; they are never run.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys
import warnings

import joblib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import read_script  # noqa: E402
from psdetect.response import ResponseEngine  # noqa: E402

MODEL = os.path.join(os.path.dirname(__file__), "..", "models", "ensemble.joblib")
COLOURS = {"ALLOW": "\033[92m", "ALERT": "\033[93m", "CONTAIN": "\033[91m", "ISOLATE": "\033[95m"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="script files to score (wildcards allowed)")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--audit", default=None, help="optional JSONL audit log path")
    args = ap.parse_args()
    if not os.path.exists(args.model):
        sys.exit("No saved model found. Run:  python demo/train_model.py --data data/mpsd")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            bundle = joblib.load(args.model)
    except Exception as exc:  # usually a scikit-learn version mismatch
        sys.exit(f"Could not load the saved model ({exc}).\nIt was built with scikit-learn 1.9.1; install that "
                 "version, or retrain it:  python demo/train_model.py --data data/mpsd")
    engine = ResponseEngine(bundle["model"], audit_path=args.audit, dry_run=True)
    paths = [p for pat in args.files for p in (glob.glob(pat) or [pat])]
    os.system("")  # enables colour codes in the Windows console
    for i, path in enumerate(paths):
        event = {"EventID": 4104, "ScriptBlockId": f"scan-{i + 1}", "ScriptBlockText": read_script(path),
                 "Computer": os.environ.get("COMPUTERNAME", "localhost"), "ProcessId": None, "Path": path}
        d = engine.handle(event)
        c = COLOURS.get(d.tier, "")
        print(f"\n{os.path.basename(path)}\n  score {d.score:.3f}   tier {c}{d.tier}\033[0m   ({d.latency_ms} ms)")
        print("  ATT&CK : " + (", ".join(f"{t['id']} {t['name']}" for t in d.techniques) or "-"))
        print("  actions: " + ", ".join(f"{a['type']} ({a['status']})" for a in d.actions))
        if d.iocs["urls"] or d.iocs["ips"]:
            print(f"  IOCs   : {d.iocs['urls'] + d.iocs['ips']}")
        if d.analyst_approval_required:
            print("  host isolation waits for analyst approval")


if __name__ == "__main__":
    main()
