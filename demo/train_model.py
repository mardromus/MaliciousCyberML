"""Trains the detection ensemble on the whole cleaned MPSD corpus and saves it
to models/ensemble.joblib, so demo/scan.py can score scripts without the dataset.
Usage:  python demo/train_model.py --data data/mpsd
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import joblib
import sklearn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import load_mpsd  # noqa: E402
from psdetect.models import SoftVotingEnsemble  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "models", "ensemble.joblib")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/mpsd")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()
    df, rep = load_mpsd(args.data)
    print(f"cleaned dataset: {rep.final_counts}")
    t0 = time.perf_counter()
    model = SoftVotingEnsemble().fit(df["text"].tolist(), df["label"].to_numpy())
    print(f"trained in {time.perf_counter() - t0:.1f} s")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    joblib.dump({"model": model, "sklearn_version": sklearn.__version__}, args.out, compress=3)
    print(f"saved {os.path.abspath(args.out)} ({os.path.getsize(args.out) / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
