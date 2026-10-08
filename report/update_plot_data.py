"""Refreshes the data blocks embedded in main.tex from results/*.json, and
orders the bibliography by first citation (IEEE convention).

Every block in main.tex is delimited by
    %<<BEGIN name>>
    ...
    %<<END name>>
and only the lines between the markers are rewritten, so the document stays a
single self-contained file that compiles on Overleaf without extra uploads.

Usage:  python report/update_plot_data.py
"""
from __future__ import annotations

import json
import os
import re

import numpy as np
import pandas as pd

ROOT = os.path.join(os.path.dirname(__file__), "..")
TEX = os.path.join(os.path.dirname(__file__), "main.tex")
RES = os.path.join(ROOT, "results")

R = json.load(open(os.path.join(RES, "metrics.json")))
S = json.load(open(os.path.join(RES, "response_summary.json")))
MT = json.load(open(os.path.join(RES, "mixed_training.json")))

MODELS = ["Handcrafted + LR", "Handcrafted + RF", "Handcrafted + HGB", "Char TF-IDF + LR",
          "Ensemble (TF-IDF LR + RF)"]
SHORT = {"Handcrafted + LR": "HC + LR", "Handcrafted + RF": "HC + RF", "Handcrafted + HGB": "HC + HGB",
         "Char TF-IDF + LR": "TF-IDF + LR", "Ensemble (TF-IDF LR + RF)": "Ensemble"}
PRETTY = {
    "ratio_whitespace": "Whitespace ratio", "log_lines": "Line count", "ratio_special": "Special-char. ratio",
    "mean_line_len": "Mean line length", "ratio_digit": "Digit ratio", "ratio_brace": "Brace ratio",
    "log_max_line_len": "Longest line", "ind_win32_api": "Win32 API indicators", "var_density": "Variable density",
    "log_longest_token": "Longest token", "ratio_upper": "Upper-case ratio", "ratio_plus": "Plus-sign ratio",
    "log_length": "Script length", "ratio_alpha": "Alphabetic ratio", "entropy": "Shannon entropy",
    "ratio_quote": "Quote ratio", "ratio_backtick": "Backtick ratio", "comment_ratio": "Comment ratio",
}


def coords(pairs, fmt="{:.4g}"):
    out = []
    for x, y in pairs:
        xs = x if isinstance(x, str) else fmt.format(x)
        ys = y if isinstance(y, str) else fmt.format(y)
        out.append(f"({xs},{ys})")
    lines, cur = [], ""
    for c in out:
        if len(cur) + len(c) > 90:
            lines.append(cur)
            cur = ""
        cur += c + " "
    lines.append(cur)
    return "\n".join("  " + l.rstrip() for l in lines if l.strip())


def roc_block(model):
    r = R["roc_curves"][model]
    fpr = np.clip(np.array(r["fpr"]), 1e-4, 1.0)
    tpr = np.array(r["tpr"])
    grid = np.logspace(-4, 0, 61)
    pts = [(g, float(tpr[fpr <= g].max()) if (fpr <= g).any() else 0.0) for g in grid]
    return "\\addplot coordinates {\n" + coords(pts) + "\n};"


def blocks():
    b = {}
    for i, m in enumerate(MODELS):
        b[f"roc{i}"] = roc_block(m)

    c = R["cleaning"]
    b["dataset"] = "\n".join([
        "\\addplot[fill=lightblue,draw=lightblue] coordinates {(Malicious,%d) (Benign,%d)};" % (
            c["raw_counts"]["malicious_pure"], c["raw_counts"]["powershell_benign_dataset"]),
        "\\addplot[fill=midblue,draw=midblue] coordinates {(Malicious,%d) (Benign,%d)};" % (
            c["final_counts"]["malicious_pure"], c["final_counts"]["powershell_benign_dataset"]),
        "\\addplot[fill=navy,draw=navy] coordinates {(Malicious,%d) (Benign,%d)};" % (
            c["skeleton_groups"]["malicious_pure"], c["skeleton_groups"]["powershell_benign_dataset"]),
    ])

    imp = R["rf_feature_importance"][:12][::-1]
    names = [PRETTY.get(t["feature"], t["feature"]) for t in imp]
    b["imp_coords"] = "symbolic y coords={" + ",".join(names) + "},"
    b["imp"] = "\\addplot[fill=midblue,draw=midblue] coordinates {\n" + coords(
        [(t["importance"], "{" + n + "}") for t, n in zip(imp, names)], "{:.3f}") + "\n};"

    order = MODELS[::-1]
    sy = "symbolic y coords={" + ",".join(SHORT[m] for m in order) + "},"
    b["proto_coords"] = sy
    b["proto"] = "\n".join([
        "\\addplot[fill=lightblue,draw=lightblue] coordinates {" + " ".join(
            f"({R['naive_random_split'][m]['tpr_at_fpr_1pct']:.4f},{{{SHORT[m]}}})" for m in order) + "};",
        "\\addplot[fill=navy,draw=navy] coordinates {" + " ".join(
            f"({R['group_split'][m]['tpr_at_fpr_1pct']:.4f},{{{SHORT[m]}}})" for m in order) + "};",
    ])
    b["mixed_coords"] = sy
    b["mixed"] = "\n".join([
        "\\addplot[fill=lightblue,draw=lightblue] coordinates {" + " ".join(
            f"({100 * R['mixed_embedded']['detection_rate'][m]:.1f},{{{SHORT[m]}}})" for m in order) + "};",
        "\\addplot[fill=navy,draw=navy] coordinates {" + " ".join(
            f"({100 * MT['mixed_detection_rate'][m]:.1f},{{{SHORT[m]}}})" for m in order) + "};",
    ])

    df = pd.read_csv(os.path.join(RES, "oof_scores.csv"))
    s = df["Ensemble (TF-IDF LR + RF)"].to_numpy()
    y = df["label"].to_numpy()
    edges = np.linspace(0, 1, 41)
    hb, _ = np.histogram(s[y == 0], bins=edges)
    hm, _ = np.histogram(s[y == 1], bins=edges)
    ben = [(edges[i], int(v)) for i, v in enumerate(hb)] + [(1.0, int(hb[-1]))]
    mal = [(edges[i], max(int(v), 0.8)) for i, v in enumerate(hm)] + [(1.0, max(int(hm[-1]), 0.8))]
    b["hist"] = ("\\addplot[ybar interval,fill=lightblue,draw=lightblue] coordinates {\n" + coords(ben) +
                 "\n};\n\\addplot[const plot,navy,thick] coordinates {\n" + coords(mal) + "\n};")

    tiers = ["ALLOW", "ALERT", "CONTAIN", "ISOLATE"]
    fills = ["paleblue", "lightblue", "midblue", "navy"]
    rows = []
    for t, f in zip(tiers, fills):
        vals = []
        for cls, lab in (("benign", "Benign"), ("malicious", "Malicious")):
            tot = sum(S["tier_counts"][cls].values())
            vals.append(f"({100 * S['tier_counts'][cls].get(t, 0) / tot:.2f},{lab})")
        rows.append(f"\\addplot[fill={f},draw=white] coordinates {{{' '.join(vals)}}};")
    b["tiers"] = "\n".join(rows)
    return b


def order_bibliography(tex: str) -> str:
    body = tex.split("\\begin{thebibliography}")[0]
    cited = []
    for group in re.findall(r"\\cite\{([^}]*)\}", body):
        for k in group.split(","):
            k = k.strip()
            if k and k not in cited:
                cited.append(k)
    m = re.search(r"(\\begin\{thebibliography\}\{\d+\}\n)(.*?)(\n\\end\{thebibliography\})", tex, re.S)
    items = re.split(r"\n(?=\\bibitem\{)", m.group(2).strip())
    by_key = {re.match(r"\\bibitem\{([^}]*)\}", it).group(1): it for it in items}
    missing = [k for k in cited if k not in by_key]
    unused = [k for k in by_key if k not in cited]
    if missing or unused:
        raise SystemExit(f"bibliography mismatch: missing={missing} unused={unused}")
    ordered = "\n\n".join(by_key[k] for k in cited)
    return tex[:m.start(2)] + ordered + tex[m.end(2):]


def main():
    tex = open(TEX).read()
    for name, content in blocks().items():
        pat = re.compile(r"(%<<BEGIN " + re.escape(name) + r">>\n)(.*?)(%<<END " + re.escape(name) + r">>)", re.S)
        if not pat.search(tex):
            raise SystemExit("marker not found: " + name)
        tex = pat.sub(lambda mm: mm.group(1) + content + "\n" + mm.group(3), tex)
    tex = order_bibliography(tex)
    open(TEX, "w").write(tex)
    print("main.tex updated")


if __name__ == "__main__":
    main()
