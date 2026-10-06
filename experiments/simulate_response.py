"""End-to-end simulation of the automated response loop.

The ensemble is trained on four of the five group-aware folds produced by
run_experiments.py; the fifth (never seen in training) is replayed as a stream
of Event ID 4104 script-block records through the ResponseEngine in dry-run
mode. Aggregate outcomes are written to results/response_summary.json.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import load_mpsd  # noqa: E402
from psdetect.models import SoftVotingEnsemble  # noqa: E402
from psdetect.response import Policy, ResponseEngine  # noqa: E402

HOLDOUT_FOLD = 4


def make_event(text: str, i: int, rng: random.Random) -> dict:
    host = f"WS-{rng.randint(1, 60):03d}"
    return {
        "EventID": 4104,
        "ScriptBlockId": str(uuid.UUID(int=rng.getrandbits(128))),
        "ScriptBlockText": text,
        "Computer": host,
        "User": f"CORP\\user{rng.randint(1, 400):03d}",
        "ProcessId": rng.randint(1000, 65000),
        "Path": f"C:\\Users\\Public\\script_{i}.ps1" if rng.random() < 0.6 else "",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/mpsd")
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    df, _ = load_mpsd(args.data)
    folds = pd.read_csv(os.path.join(args.out, "oof_scores.csv"))[["subset", "file", "fold"]]
    df = df.merge(folds, on=["subset", "file"], how="left")
    train = df[df["fold"] != HOLDOUT_FOLD]
    test = df[df["fold"] == HOLDOUT_FOLD].sample(frac=1.0, random_state=7)

    t0 = time.perf_counter()
    model = SoftVotingEnsemble().fit(train["text"].tolist(), train["label"].to_numpy())
    train_s = time.perf_counter() - t0

    audit = os.path.join(args.out, "response_audit.jsonl")
    if os.path.exists(audit):
        os.remove(audit)
    engine = ResponseEngine(model, Policy(), audit_path=audit, dry_run=True)
    rng = random.Random(2026)

    rows = []
    t_stream = time.perf_counter()
    for i, (text, label) in enumerate(zip(test["text"], test["label"])):
        d = engine.handle(make_event(text, i, rng))
        rows.append({"label": int(label), "tier": d.tier, "score": d.score,
                     "latency_ms": d.latency_ms, "n_actions": len(d.actions),
                     "n_techniques": len(d.techniques),
                     "techniques": [t["id"] for t in d.techniques],
                     "approval": d.analyst_approval_required})
    stream_s = time.perf_counter() - t_stream
    r = pd.DataFrame(rows)

    def share(mask_label, tiers):
        sub = r[r["label"] == mask_label]
        return float(sub["tier"].isin(tiers).mean())

    tech_counts = (r[r["tier"].isin(["CONTAIN", "ISOLATE"])]["techniques"]
                   .explode().value_counts().to_dict())
    summary = {
        "train_size": int(len(train)), "replayed_events": int(len(r)),
        "replayed_malicious": int((r["label"] == 1).sum()),
        "replayed_benign": int((r["label"] == 0).sum()),
        "train_seconds": train_s,
        "throughput_events_per_s": len(r) / stream_s,
        "latency_ms": {"mean": float(r["latency_ms"].mean()),
                       "median": float(r["latency_ms"].median()),
                       "p95": float(np.percentile(r["latency_ms"], 95)),
                       "max": float(r["latency_ms"].max())},
        "tier_counts": {lab: r[r["label"] == v]["tier"].value_counts().to_dict()
                        for lab, v in (("benign", 0), ("malicious", 1))},
        "malicious_contained_rate": share(1, ["CONTAIN", "ISOLATE"]),
        "malicious_alerted_or_higher_rate": share(1, ["ALERT", "CONTAIN", "ISOLATE"]),
        "benign_contained_rate": share(0, ["CONTAIN", "ISOLATE"]),
        "benign_alert_rate": share(0, ["ALERT"]),
        "isolations_pending_analyst": int(r["approval"].sum()),
        "attack_techniques_in_contained_events": {k: int(v) for k, v in tech_counts.items()},
        "mean_actions_per_contained_event": float(
            r[r["tier"].isin(["CONTAIN", "ISOLATE"])]["n_actions"].mean()),
    }
    with open(os.path.join(args.out, "response_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
