"""Runs every experiment reported in the case study and writes metrics to
results/metrics.json. Usage:  python experiments/run_experiments.py --data data/mpsd
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import exact_key, load_mpsd, read_script  # noqa: E402
from psdetect.features import HANDCRAFTED_NAMES, HandcraftedFeatures  # noqa: E402
from psdetect.models import (MODEL_FACTORIES, SEED, SoftVotingEnsemble,  # noqa: E402
                             handcrafted_rf)

K = 5


def metrics(y, p, thr=0.5) -> dict:
    yhat = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    fpr, tpr, _ = roc_curve(y, p)
    return {
        "accuracy": accuracy_score(y, yhat),
        "precision": precision_score(y, yhat, zero_division=0),
        "recall": recall_score(y, yhat),
        "f1": f1_score(y, yhat),
        "roc_auc": roc_auc_score(y, p),
        "fpr": fp / (fp + tn),
        "tpr_at_fpr_1pct": float(np.interp(0.01, fpr, tpr)),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def run_cv(texts, H, y, splits, out_prefix=""):
    """Out-of-fold probabilities for every model. Hand-crafted features are
    pre-computed (they are stateless); TF-IDF is refit inside each fold."""
    oof = {name: np.zeros(len(y)) for name in list(MODEL_FACTORIES) + ["Ensemble (TF-IDF LR + RF)"]}
    timing = {name: {"fit_s": 0.0, "predict_s": 0.0} for name in oof}
    for k, (tr, te) in enumerate(splits):
        print(f"{out_prefix} fold {k + 1}/{len(splits)}", flush=True)
        fold_probs = {}
        for name, factory in MODEL_FACTORIES.items():
            pipe = factory()
            t0 = time.perf_counter()
            if name.startswith("Handcrafted"):
                clf = pipe[1:]  # drop the stateless feature step, reuse cached H
                clf.fit(H[tr], y[tr])
                t1 = time.perf_counter()
                p = clf.predict_proba(H[te])[:, 1]
            else:
                pipe.fit([texts[i] for i in tr], y[tr])
                t1 = time.perf_counter()
                p = pipe.predict_proba([texts[i] for i in te])[:, 1]
            t2 = time.perf_counter()
            timing[name]["fit_s"] += t1 - t0
            timing[name]["predict_s"] += t2 - t1
            oof[name][te] = p
            fold_probs[name] = p
        ens = 0.5 * fold_probs["Char TF-IDF + LR"] + 0.5 * fold_probs["Handcrafted + RF"]
        oof["Ensemble (TF-IDF LR + RF)"][te] = ens
    return oof, timing


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/mpsd")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    results = {}

    # ---------------- data ----------------
    df, rep = load_mpsd(args.data)
    results["cleaning"] = rep.__dict__
    print(rep)
    texts = df["text"].tolist()
    y = df["label"].to_numpy()
    groups = df["group"].to_numpy()
    t0 = time.perf_counter()
    H = HandcraftedFeatures().transform(texts)
    results["feature_extraction_ms_per_script"] = (time.perf_counter() - t0) * 1000 / len(texts)

    # ------------- Exp 1: naive evaluation on raw, duplicated data -------------
    raw = []
    for sub in ("malicious_pure", "powershell_benign_dataset"):
        folder = os.path.join(args.data, sub)
        for name in sorted(os.listdir(folder)):
            raw.append((read_script(os.path.join(folder, name)), int(sub.startswith("mal"))))
    raw_texts = [t for t, _ in raw]
    raw_y = np.array([l for _, l in raw])
    raw_H = HandcraftedFeatures().transform(raw_texts)
    skf = StratifiedKFold(K, shuffle=True, random_state=SEED)
    naive_oof, _ = run_cv(raw_texts, raw_H, raw_y, list(skf.split(raw_texts, raw_y)), "[naive]")
    results["naive_random_split"] = {m: metrics(raw_y, p) for m, p in naive_oof.items()}

    # ------------- Exp 2: deduplicated, group-aware evaluation -------------
    sgkf = StratifiedGroupKFold(K, shuffle=True, random_state=SEED)
    splits = list(sgkf.split(texts, y, groups))
    oof, timing = run_cv(texts, H, y, splits, "[group]")
    results["group_split"] = {m: metrics(y, p) for m, p in oof.items()}
    results["timing"] = timing
    fold_of = np.zeros(len(y), dtype=int)
    for k, (_, te) in enumerate(splits):
        fold_of[te] = k
    per_fold = {}
    for m, p in oof.items():
        per_fold[m] = [metrics(y[fold_of == k], p[fold_of == k])["f1"] for k in range(K)]
    results["group_split_f1_per_fold"] = per_fold

    roc = {}
    for m, p in oof.items():
        fpr, tpr, _ = roc_curve(y, p)
        idx = np.linspace(0, len(fpr) - 1, min(len(fpr), 400)).astype(int)
        roc[m] = {"fpr": fpr[idx].tolist(), "tpr": tpr[idx].tolist()}
    results["roc_curves"] = roc
    pd.DataFrame({"subset": df["subset"], "file": df["file"], "label": y, "fold": fold_of,
                  **{m: p for m, p in oof.items()}}).to_csv(
        os.path.join(args.out, "oof_scores.csv"), index=False)

    # ------------- Exp 3: malicious code embedded in benign scripts -------------
    # A mixed sample is "<malicious id>_<benign id>.ps1". It is scored by models
    # trained on the folds that did NOT contain its malicious parent.
    key_to_fold = {}
    for i, row in df.iterrows():
        key_to_fold[row["exact"]] = fold_of[i]
    mixed_dir = os.path.join(args.data, "mixed_malicious")
    mixed_by_fold = {k: [] for k in range(K)}
    skipped = 0
    for name in sorted(os.listdir(mixed_dir)):
        parts = name[:-4].split("_")
        if len(parts) != 2:
            skipped += 1
            continue
        parent = os.path.join(args.data, "malicious_pure", parts[0] + ".ps1")
        k = key_to_fold.get(exact_key(read_script(parent)))
        if k is None:
            skipped += 1
            continue
        mixed_by_fold[k].append(read_script(os.path.join(mixed_dir, name)))
    mixed_scores = {m: [] for m in oof}
    for k, (tr, te) in enumerate(splits):
        print(f"[mixed] fold {k + 1}/{K}", flush=True)
        mt = mixed_by_fold[k]
        if not mt:
            continue
        Hm = HandcraftedFeatures().transform(mt)
        probs = {}
        for name, factory in MODEL_FACTORIES.items():
            pipe = factory()
            if name.startswith("Handcrafted"):
                clf = pipe[1:]
                clf.fit(H[tr], y[tr])
                probs[name] = clf.predict_proba(Hm)[:, 1]
            else:
                pipe.fit([texts[i] for i in tr], y[tr])
                probs[name] = pipe.predict_proba(mt)[:, 1]
        probs["Ensemble (TF-IDF LR + RF)"] = 0.5 * probs["Char TF-IDF + LR"] + 0.5 * probs["Handcrafted + RF"]
        for m, p in probs.items():
            mixed_scores[m].extend(p.tolist())
    results["mixed_embedded"] = {
        "n_evaluated": len(mixed_scores["Handcrafted + RF"]), "n_skipped": skipped,
        "detection_rate": {m: float(np.mean(np.array(s) >= 0.5)) for m, s in mixed_scores.items()},
        "mean_score": {m: float(np.mean(s)) for m, s in mixed_scores.items()},
    }

    # ------------- Explainability: RF importances on the full cleaned set -------------
    rf = clone(handcrafted_rf()[1:]).fit(H, y)
    imp = sorted(zip(HANDCRAFTED_NAMES, rf[-1].feature_importances_), key=lambda x: -x[1])
    results["rf_feature_importance"] = [{"feature": f, "importance": float(v)} for f, v in imp]
    from psdetect.models import tfidf_lr
    lr = tfidf_lr().fit(texts, y)
    vocab = np.array(lr.named_steps["tfidf"].get_feature_names_out())
    coef = lr.named_steps["clf"].coef_[0]
    order = np.argsort(coef)
    results["lr_top_benign_ngrams"] = [vocab[i] for i in order[:15]]
    results["lr_top_malicious_ngrams"] = [vocab[i] for i in order[::-1][:15]]

    # ------------- Response tiers on out-of-fold ensemble scores -------------
    from psdetect.response import Policy
    pol = Policy()
    p = oof["Ensemble (TF-IDF LR + RF)"]
    tiers = np.select([p >= pol.contain_threshold, p >= pol.alert_threshold], [2, 1], 0)
    results["tier_distribution"] = {
        cls: {t: int(((tiers == v) & (y == lab)).sum()) for t, v in
              (("allow", 0), ("alert", 1), ("contain_or_isolate", 2))}
        for cls, lab in (("benign", 0), ("malicious", 1))
    }

    with open(os.path.join(args.out, "metrics.json"), "w") as fh:
        json.dump(results, fh, indent=2, default=float)
    print(json.dumps({k: v for k, v in results.items() if k not in ("roc_curves",)},
                     indent=1, default=float)[:6000])


if __name__ == "__main__":
    main()
