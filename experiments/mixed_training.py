"""Mitigation experiment for the embedded-code weakness found in Exp 3.

Same family-aware folds as run_experiments.py. In fold k the training set is
the clean training folds PLUS mixed samples whose malicious parent AND benign
host both lie in the training folds (so nothing about a test script leaks
into training). Evaluation:
  * clean test fold (does augmentation hurt precision on ordinary scripts?)
  * mixed samples whose malicious parent lies in test fold k (as in Exp 3)
Output: results/mixed_training.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import exact_key, load_mpsd, read_script  # noqa: E402
from psdetect.features import HandcraftedFeatures  # noqa: E402
from psdetect.models import MODEL_FACTORIES  # noqa: E402

sys.path.insert(0, os.path.dirname(__file__))
from run_experiments import metrics  # noqa: E402

ENS = "Ensemble (TF-IDF LR + RF)"
K = 5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/mpsd")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    df, _ = load_mpsd(args.data)
    folds = pd.read_csv(os.path.join(args.out, "oof_scores.csv"))[["subset", "file", "fold"]]
    df = df.merge(folds, on=["subset", "file"], how="left")
    key_to_fold = dict(zip(df["exact"], df["fold"]))

    mixed = []
    mixed_dir = os.path.join(args.data, "mixed_malicious")
    for name in sorted(os.listdir(mixed_dir)):
        parts = name[:-4].split("_")
        if len(parts) != 2:
            continue
        mal = os.path.join(args.data, "malicious_pure", parts[0] + ".ps1")
        ben = os.path.join(args.data, "powershell_benign_dataset", parts[1] + ".ps1")
        fm = key_to_fold.get(exact_key(read_script(mal)))
        fb = key_to_fold.get(exact_key(read_script(ben))) if os.path.exists(ben) else None
        if fm is None:
            continue
        mixed.append({"text": read_script(os.path.join(mixed_dir, name)),
                      "mal_fold": int(fm), "ben_fold": -1 if fb is None else int(fb)})
    mx = pd.DataFrame(mixed)
    texts = df["text"].tolist()
    y = df["label"].to_numpy()
    fold = df["fold"].to_numpy()
    H = HandcraftedFeatures().transform(texts)
    Hm = HandcraftedFeatures().transform(mx["text"].tolist())

    clean_oof = {m: np.zeros(len(y)) for m in list(MODEL_FACTORIES) + [ENS]}
    mixed_scores = {m: np.zeros(len(mx)) for m in clean_oof}
    n_aug = []
    for k in range(K):
        print(f"[mixed-aware] fold {k + 1}/{K}", flush=True)
        tr, te = np.where(fold != k)[0], np.where(fold == k)[0]
        # unknown benign host (-1) is excluded from training to rule out leakage
        aug = np.where((mx["mal_fold"] != k) & (mx["ben_fold"] != k) & (mx["ben_fold"] >= 0))[0]
        mte = np.where(mx["mal_fold"] == k)[0]
        n_aug.append(len(aug))
        Xtr_text = [texts[i] for i in tr] + [mx["text"].iat[i] for i in aug]
        Htr = np.vstack([H[tr], Hm[aug]])
        ytr = np.concatenate([y[tr], np.ones(len(aug), dtype=int)])
        probs_clean, probs_mixed = {}, {}
        for name, factory in MODEL_FACTORIES.items():
            pipe = factory()
            if name.startswith("Handcrafted"):
                clf = pipe[1:]
                clf.fit(Htr, ytr)
                probs_clean[name] = clf.predict_proba(H[te])[:, 1]
                probs_mixed[name] = clf.predict_proba(Hm[mte])[:, 1]
            else:
                pipe.fit(Xtr_text, ytr)
                probs_clean[name] = pipe.predict_proba([texts[i] for i in te])[:, 1]
                probs_mixed[name] = pipe.predict_proba([mx["text"].iat[i] for i in mte])[:, 1]
        for d in (probs_clean, probs_mixed):
            d[ENS] = 0.5 * d["Char TF-IDF + LR"] + 0.5 * d["Handcrafted + RF"]
        for m in clean_oof:
            clean_oof[m][te] = probs_clean[m]
            mixed_scores[m][mte] = probs_mixed[m]

    res = {
        "augmented_training_samples_per_fold": n_aug,
        "clean_test": {m: metrics(y, p) for m, p in clean_oof.items()},
        "mixed_detection_rate": {m: float(np.mean(p >= 0.5)) for m, p in mixed_scores.items()},
        "mixed_alert_or_higher_rate": {m: float(np.mean(p >= 0.30)) for m, p in mixed_scores.items()},
        "n_mixed_evaluated": int(len(mx)),
    }
    with open(os.path.join(args.out, "mixed_training.json"), "w") as fh:
        json.dump(res, fh, indent=2, default=float)
    print(json.dumps({k: v for k, v in res.items() if k != "clean_test"}, indent=1))
    for m, v in res["clean_test"].items():
        print(m, {k: round(v[k], 4) for k in ("f1", "precision", "recall", "fpr", "tpr_at_fpr_1pct")})


if __name__ == "__main__":
    main()
