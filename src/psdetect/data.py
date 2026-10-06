"""Dataset loading, cleaning and near-duplicate grouping for the MPSD corpus."""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

import pandas as pd

LABEL_DIRS = {
    "malicious_pure": 1,
    "mixed_malicious": 1,
    "powershell_benign_dataset": 0,
}

MAX_CHARS = 200_000  # very large files are truncated to bound feature extraction time

_VAR_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_:]*")
_NUM_RE = re.compile(r"0x[0-9a-fA-F]+|\b\d+\b")
_WS_RE = re.compile(r"\s+")


def read_script(path: str) -> str:
    """Read a script as text. Byte-order marks are removed because in MPSD they
    occur only in benign-derived files and would act as a label shortcut."""
    raw = open(path, "rb").read()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16", errors="ignore")
    else:
        text = raw.decode("utf-8", errors="ignore")
    return text.lstrip("﻿")[:MAX_CHARS]


def exact_key(text: str) -> str:
    """Hash after whitespace and case normalisation (exact-duplicate key)."""
    return hashlib.sha256(_WS_RE.sub(" ", text).strip().lower().encode()).hexdigest()


def skeleton_key(text: str) -> str:
    """Hash of a structural skeleton: variable names and numeric literals are
    abstracted, so scripts that differ only by renamed variables or changed
    constants share a key. Used to keep near-duplicates in the same fold."""
    t = text.lower()
    t = _VAR_RE.sub("$v", t)
    t = _NUM_RE.sub("0", t)
    t = _WS_RE.sub("", t)
    return hashlib.sha256(t[:20_000].encode()).hexdigest()


@dataclass
class CleaningReport:
    raw_counts: dict
    exact_duplicates_removed: int
    label_conflicts_removed: int
    final_counts: dict
    skeleton_groups: dict


def load_mpsd(root: str, subsets=("malicious_pure", "powershell_benign_dataset")):
    """Load the chosen MPSD subsets, remove exact duplicates and label conflicts,
    and attach a near-duplicate group id to every sample."""
    rows = []
    for sub in subsets:
        folder = os.path.join(root, sub)
        for name in sorted(os.listdir(folder)):
            text = read_script(os.path.join(folder, name))
            rows.append({"subset": sub, "file": name, "label": LABEL_DIRS[sub], "text": text})
    df = pd.DataFrame(rows)
    raw_counts = df.groupby("subset").size().to_dict()

    df["exact"] = df["text"].map(exact_key)
    # A script that appears under both labels cannot be trusted either way.
    conflict_keys = set(df.groupby("exact")["label"].nunique().loc[lambda s: s > 1].index)
    n_conflict = int(df["exact"].isin(conflict_keys).sum())
    df = df[~df["exact"].isin(conflict_keys)]
    before = len(df)
    df = df.drop_duplicates("exact").reset_index(drop=True)
    n_dupes = before - len(df)

    df["skeleton"] = df["text"].map(skeleton_key)
    df["group"] = pd.factorize(df["skeleton"])[0]
    groups = {
        sub: int(df.loc[df["subset"] == sub, "group"].nunique()) for sub in subsets
    }
    report = CleaningReport(
        raw_counts=raw_counts,
        exact_duplicates_removed=int(n_dupes),
        label_conflicts_removed=n_conflict,
        final_counts=df.groupby("subset").size().to_dict(),
        skeleton_groups=groups,
    )
    return df, report
