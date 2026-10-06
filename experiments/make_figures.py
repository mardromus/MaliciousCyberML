"""Builds report figures from results/*.json. Palette is restricted to black and
blue shades (report colour rule); series identity is also carried by line style
or direct labels so no figure relies on colour alone."""
from __future__ import annotations

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

RES = "results"
FIG = os.path.join(RES, "figures")
os.makedirs(FIG, exist_ok=True)

INK = "#1a1a1a"
MUTED = "#555555"
NAVY = "#0d366b"
BLUE = "#2a78d6"
MID = "#5598e7"
LIGHT = "#86b6ef"
PALE = "#cde2fb"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 10,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": "#e3e3e3",
    "grid.linewidth": 0.6,
    "axes.axisbelow": True,
    "savefig.dpi": 220,
    "savefig.bbox": "tight",
})

M = json.load(open(os.path.join(RES, "metrics.json")))
MODEL_ORDER = ["Handcrafted + LR", "Handcrafted + RF", "Handcrafted + HGB",
               "Char TF-IDF + LR", "Ensemble (TF-IDF LR + RF)"]
STYLE = {
    "Handcrafted + LR": dict(color=LIGHT, ls=":", lw=2),
    "Handcrafted + RF": dict(color=MID, ls="--", lw=2),
    "Handcrafted + HGB": dict(color=BLUE, ls="-.", lw=2),
    "Char TF-IDF + LR": dict(color=INK, ls=(0, (1, 1.5)), lw=2),
    "Ensemble (TF-IDF LR + RF)": dict(color=NAVY, ls="-", lw=2.4),
}


def architecture():
    fig, ax = plt.subplots(figsize=(10, 4.2))
    ax.set_xlim(0, 100)
    ax.set_ylim(-1, 44)
    ax.axis("off")

    def box(x, y, w, h, title, body, fill=PALE, edge=NAVY):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                    fc=fill, ec=edge, lw=1.2))
        ax.text(x + w / 2, y + h - 2.2, title, ha="center", va="top", fontsize=10,
                fontweight="bold", color=NAVY)
        ax.text(x + w / 2, y + h - 6.4, body, ha="center", va="top", fontsize=8.2, color=INK,
                linespacing=1.35)

    def arrow(x1, y1, x2, y2):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14,
                                     color=NAVY, lw=1.3))

    top = 24
    box(1, top, 17, 18, "1. Telemetry", "Script Block\nLogging (4104)\nAMSI buffer\nEDR process events")
    box(21, top, 17, 18, "2. Pre-processing", "BOM strip, decode\ncase + backtick\nnormalisation\ndedup / hashing")
    box(41, top, 17, 18, "3. Features", "char 3–5-gram TF-IDF\n24 statistical feats\n9 ATT&CK indicator\ngroups")
    box(61, top, 17, 18, "4. Detection", "TF-IDF + LR\nHand-crafted + RF\nsoft-voting\nrisk score p in [0, 1]")
    box(81, top, 18, 18, "5. Policy engine", "ALLOW   p < 0.30\nALERT   0.30–0.70\nCONTAIN  ≥ 0.70\nISOLATE ≥ 0.95*")
    for x in (18.8, 38.8, 58.8, 78.8):
        arrow(x, top + 9, x + 2.0, top + 9)

    box(81, 0, 18, 20, "6. Response (SOAR)",
        "log, alert SOC\nkill process\nquarantine, block hash\nblock URLs / IPs\nisolate host", fill="#ffffff")
    box(61, 0, 17, 20, "7. Analyst",
        "ATT&CK-tagged\nticket\napproves isolation\nrelabels errors", fill="#ffffff")
    box(21, 0, 36, 20, "Offline training & retraining",
        "MPSD corpus \u2192 audit / de-duplication\nfamily-aware 5-fold CV \u2192 model selection\n\u2192 fixed policy thresholds\nperiodic retraining with analyst labels",
        fill="#ffffff", edge=MUTED)
    arrow(90, top - 0.6, 90, 20.6)      # policy -> response
    arrow(80.4, 10, 78.6, 10)            # response -> analyst
    arrow(60.4, 10, 57.6, 10)            # analyst -> retraining
    arrow(52, 20.6, 64, top - 0.6)       # retraining -> detection model
    ax.text(1, 10, "* isolation also\nrequires a high-\nimpact technique\n(injection, credential\naccess, reflection)",
            ha="left", va="center", fontsize=7.5, color=MUTED, style="italic")
    fig.savefig(os.path.join(FIG, "fig1_architecture.png"))
    plt.close(fig)


def dataset():
    c = M["cleaning"]
    raw = [c["raw_counts"]["malicious_pure"], c["raw_counts"]["powershell_benign_dataset"]]
    uniq = [c["final_counts"]["malicious_pure"], c["final_counts"]["powershell_benign_dataset"]]
    fam = [c["skeleton_groups"]["malicious_pure"], c["skeleton_groups"]["powershell_benign_dataset"]]
    fig, ax = plt.subplots(figsize=(7, 3.4))
    x = np.arange(2)
    w = 0.26
    for i, (vals, col, lab) in enumerate(((raw, LIGHT, "Raw files"), (uniq, BLUE, "After exact dedup"),
                                          (fam, NAVY, "Structural families"))):
        bars = ax.bar(x + (i - 1) * w, vals, w - 0.02, color=col, label=lab)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 60, f"{v:,}", ha="center", fontsize=8, color=INK)
    ax.set_xticks(x, ["Malicious (malicious_pure)", "Benign"])
    ax.set_ylabel("Number of scripts")
    ax.legend(frameon=False, fontsize=8.5, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.12))
    ax.grid(axis="x", visible=False)
    ax.set_ylim(0, max(raw) * 1.12)
    fig.savefig(os.path.join(FIG, "fig2_dataset.png"))
    plt.close(fig)


def roc():
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    for m in MODEL_ORDER:
        r = M["roc_curves"][m]
        auc = M["group_split"][m]["roc_auc"]
        fpr = np.clip(np.array(r["fpr"]), 1e-4, 1)
        ax.plot(fpr, r["tpr"], label=f"{m} (AUC {auc:.4f})", **STYLE[m])
    ax.set_xscale("log")
    ax.set_xlim(1e-4, 1)
    ax.set_ylim(0.5, 1.005)
    ax.axvline(0.01, color=MUTED, lw=0.8, ls="--")
    ax.text(0.0108, 0.70, "FPR = 1%", fontsize=8, color=MUTED)
    ax.set_xlabel("False positive rate (log scale)")
    ax.set_ylabel("True positive rate")
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    fig.savefig(os.path.join(FIG, "fig3_roc.png"))
    plt.close(fig)


def naive_vs_group():
    fig, ax = plt.subplots(figsize=(7, 3.6))
    y = np.arange(len(MODEL_ORDER))
    naive = [M["naive_random_split"][m]["tpr_at_fpr_1pct"] for m in MODEL_ORDER]
    group = [M["group_split"][m]["tpr_at_fpr_1pct"] for m in MODEL_ORDER]
    for yi, a, b in zip(y, naive, group):
        ax.plot([b, a], [yi, yi], color=LIGHT, lw=2.2, zorder=1)
    ax.scatter(naive, y, s=46, color=LIGHT, edgecolor=NAVY, zorder=2, label="Naive random split (duplicates kept)")
    ax.scatter(group, y, s=46, color=NAVY, zorder=3, label="Deduplicated + group-aware split")
    for yi, a, b in zip(y, naive, group):
        ax.text(max(a, b) + 0.0025, yi, f"{b:.3f} → {a:.3f}", fontsize=7.8, color=INK, ha="left", va="center")
    ax.set_yticks(y, MODEL_ORDER)
    ax.set_ylim(len(MODEL_ORDER) - 0.5, -0.5)
    ax.set_xlabel("True positive rate at 1% false positive rate")
    lo = min(group + naive)
    ax.set_xlim(max(0, lo - 0.01), 1.012)
    ax.set_xticks([t for t in np.arange(0.90, 1.001, 0.02) if t >= lo - 0.01])
    ax.legend(frameon=False, fontsize=8, loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2)
    fig.savefig(os.path.join(FIG, "fig4_naive_vs_group.png"))
    plt.close(fig)


def confusion():
    g = M["group_split"]["Ensemble (TF-IDF LR + RF)"]
    cm = np.array([[g["tn"], g["fp"]], [g["fn"], g["tp"]]])
    fig, ax = plt.subplots(figsize=(3.8, 3.3))
    norm = cm / cm.sum(axis=1, keepdims=True)
    ax.imshow(norm, cmap=matplotlib.colors.LinearSegmentedColormap.from_list("b", ["#ffffff", NAVY]),
              vmin=0, vmax=1)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}\n({norm[i, j] * 100:.2f}%)", ha="center", va="center",
                    fontsize=10, color="#ffffff" if norm[i, j] > 0.5 else INK)
    ax.set_xticks([0, 1], ["Benign", "Malicious"])
    ax.set_yticks([0, 1], ["Benign", "Malicious"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)
    fig.savefig(os.path.join(FIG, "fig5_confusion.png"))
    plt.close(fig)


PRETTY = {
    "ind_win32_api": "Win32 API / injection indicators", "ind_download": "Download-cradle indicators",
    "ind_exec_dynamic": "Dynamic execution (IEX etc.)", "ind_encoding": "Encoding / compression indicators",
    "ind_defense_evasion": "Defence-evasion flags", "ind_reflection": "Reflection / Add-Type",
    "ind_network_socket": "Raw socket indicators", "ind_persistence": "Persistence indicators",
    "ind_credential": "Credential-access indicators", "log_length": "Script length (log)",
    "log_lines": "Line count (log)", "mean_line_len": "Mean line length",
    "log_max_line_len": "Longest line (log)", "entropy": "Shannon entropy",
    "ratio_alpha": "Alphabetic ratio", "ratio_digit": "Digit ratio", "ratio_upper": "Upper-case ratio",
    "ratio_whitespace": "Whitespace ratio", "ratio_special": "Special-character ratio",
    "ratio_backtick": "Backtick ratio", "ratio_plus": "'+' ratio", "ratio_quote": "Quote ratio",
    "ratio_brace": "Brace ratio", "log_longest_token": "Longest token (log)",
    "base64_blobs": "Base64-like blobs", "url_count": "URL count", "ip_count": "IP-address count",
    "var_density": "Variable density", "distinct_vars": "Distinct variables",
    "comment_ratio": "Comment-line ratio", "function_defs": "Function definitions",
    "help_keywords": "Comment-based help keywords", "has_param_block": "Has param() block",
}


def importance():
    top = M["rf_feature_importance"][:14]
    names = [PRETTY.get(t["feature"], t["feature"]) for t in top][::-1]
    vals = [t["importance"] for t in top][::-1]
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.barh(names, vals, color=BLUE, height=0.7)
    for i, v in enumerate(vals):
        ax.text(v + 0.002, i, f"{v:.3f}", va="center", fontsize=7.8, color=INK)
    ax.set_xlabel("Mean decrease in impurity (Random Forest)")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(vals) * 1.15)
    fig.savefig(os.path.join(FIG, "fig6_importance.png"))
    plt.close(fig)


def score_distribution():
    df = pd.read_csv(os.path.join(RES, "oof_scores.csv"))
    s = df["Ensemble (TF-IDF LR + RF)"]
    fig, ax = plt.subplots(figsize=(6.6, 3.4))
    bins = np.linspace(0, 1, 41)
    ax.hist(s[df["label"] == 0], bins=bins, color=LIGHT, label="Benign scripts", histtype="stepfilled")
    ax.hist(s[df["label"] == 1], bins=bins, color=NAVY, label="Malicious scripts", histtype="step", lw=1.8)
    ax.set_yscale("log")
    ax.set_ylim(0.7, 2e4)
    for t, lab in ((0.30, "ALERT"), (0.70, "CONTAIN"), (0.95, "ISOLATE*")):
        ax.axvline(t, color=INK, lw=0.9, ls="--")
        ax.text(t - 0.012, 1.2e3, lab, fontsize=8, color=INK, rotation=90, ha="right", va="bottom")
    ax.set_xlabel("Ensemble risk score (out-of-fold)")
    ax.set_ylabel("Scripts (log scale)")
    ax.legend(frameon=False, fontsize=8.5, loc="upper center", bbox_to_anchor=(0.5, 1.0))
    fig.savefig(os.path.join(FIG, "fig7_score_distribution.png"))
    plt.close(fig)


def response():
    path = os.path.join(RES, "response_summary.json")
    if not os.path.exists(path):
        return
    R = json.load(open(path))
    tiers = ["ALLOW", "ALERT", "CONTAIN", "ISOLATE"]
    cols = [PALE, LIGHT, BLUE, NAVY]
    fig, ax = plt.subplots(figsize=(7, 2.7))
    for yi, cls in enumerate(("benign", "malicious")):
        counts = R["tier_counts"][cls]
        total = sum(counts.values())
        left = 0
        for t, c in zip(tiers, cols):
            v = counts.get(t, 0) / total
            if v > 0:
                ax.barh(yi, v, left=left, color=c, edgecolor="#ffffff", lw=1.5, height=0.6)
                if v > 0.035:
                    ax.text(left + v / 2, yi, f"{t}\n{v * 100:.1f}%", ha="center", va="center", fontsize=7.6,
                            color="#ffffff" if c in (BLUE, NAVY) else INK)
            left += v
    ax.set_yticks([0, 1], [f"Benign (n={sum(R['tier_counts']['benign'].values())})",
                           f"Malicious (n={sum(R['tier_counts']['malicious'].values())})"])
    ax.set_xlim(0, 1)
    ax.set_xlabel("Share of replayed events")
    ax.grid(False)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(facecolor=c, edgecolor=MUTED, lw=0.4, label=t) for t, c in zip(tiers, cols)],
              frameon=False, fontsize=8, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.32))
    fig.savefig(os.path.join(FIG, "fig8_response_tiers.png"))
    plt.close(fig)


if __name__ == "__main__":
    architecture()
    dataset()
    roc()
    naive_vs_group()
    confusion()
    importance()
    score_distribution()
    response()
    print("figures written to", FIG)
