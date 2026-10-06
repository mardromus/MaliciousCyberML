"""Characterises the ensemble's out-of-fold errors (no script content is
written out, only aggregate properties). Output: results/error_analysis.json"""
from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import load_mpsd  # noqa: E402
from psdetect.features import INDICATOR_GROUPS, indicator_hits, normalise  # noqa: E402

ENS = "Ensemble (TF-IDF LR + RF)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/mpsd")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()
    df, _ = load_mpsd(args.data)
    oof = pd.read_csv(os.path.join(args.out, "oof_scores.csv"))[["subset", "file", ENS]]
    df = df.merge(oof, on=["subset", "file"]).rename(columns={ENS: "p"})
    df["length"] = df["text"].str.len()
    hits = df["text"].map(lambda t: indicator_hits(normalise(t)))
    df["n_groups"] = hits.map(lambda h: sum(v > 0 for v in h.values()))
    for g in INDICATOR_GROUPS:
        df["g_" + g] = hits.map(lambda h, g=g: h[g] > 0)

    sets = {
        "false_positive": df[(df.label == 0) & (df.p >= 0.5)],
        "false_negative": df[(df.label == 1) & (df.p < 0.5)],
        "true_positive": df[(df.label == 1) & (df.p >= 0.5)],
        "true_negative": df[(df.label == 0) & (df.p < 0.5)],
    }
    out = {}
    for name, s in sets.items():
        out[name] = {
            "count": int(len(s)),
            "median_length": int(s["length"].median()),
            "mean_indicator_groups": round(float(s["n_groups"].mean()), 2),
            "share_with_no_indicator": round(float((s["n_groups"] == 0).mean()), 3),
            "group_presence": {g: round(float(s["g_" + g].mean()), 3) for g in INDICATOR_GROUPS},
        }
    fn, fp = sets["false_negative"], sets["false_positive"]
    out["false_negative_still_alerted_share"] = round(float((fn.p >= 0.30).mean()), 3)
    out["false_positive_contained_share"] = round(float((fp.p >= 0.70).mean()), 3)
    with open(os.path.join(args.out, "error_analysis.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
