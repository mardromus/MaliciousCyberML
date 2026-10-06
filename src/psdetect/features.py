"""Feature extraction for PowerShell script classification.

Two complementary views are produced:
  * a normalised text view, consumed by character n-gram TF-IDF, and
  * a vector of interpretable, hand-crafted statistical/behavioural features.
"""
from __future__ import annotations

import math
import re
from collections import Counter

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

_WS = re.compile(r"[ \t]+")


def normalise(text: str) -> str:
    """Light, semantics-preserving normalisation. PowerShell is case-insensitive
    and ignores the backtick escape inside identifiers, so both are folded."""
    t = text.replace("`", "").lower()
    return _WS.sub(" ", t)


# Behavioural indicator groups. Each entry is a regex applied to the normalised
# text; counts are summed per group. Groups mirror MITRE ATT&CK tactics so the
# same signals can be reused by the response engine for technique mapping.
INDICATOR_GROUPS: dict[str, list[str]] = {
    "exec_dynamic": [r"\binvoke-expression\b", r"\biex\b", r"\binvoke-command\b",
                     r"\bstart-process\b", r"\bscriptblock\]::create\b"],
    "download": [r"downloadstring", r"downloadfile", r"downloaddata", r"net\.webclient",
                 r"\binvoke-webrequest\b", r"\biwr\b", r"bitstransfer", r"\binvoke-restmethod\b"],
    "encoding": [r"frombase64string", r"-enc(odedcommand)?\b", r"-bxor\b",
                 r"gzipstream", r"deflatestream", r"io\.compression", r"\[char\]\s*\d+"],
    "win32_api": [r"virtualalloc", r"createthread", r"writeprocessmemory",
                  r"getprocaddress", r"getdelegateforfunctionpointer", r"dllimport",
                  r"kernel32", r"memset", r"marshal\]::copy"],
    "defense_evasion": [r"-w(indowstyle)?\s+hidden", r"-nop(rofile)?\b", r"\bbypass\b",
                        r"-executionpolicy", r"\bamsi", r"set-mppreference",
                        r"-noni(nteractive)?\b"],
    "persistence": [r"schtasks", r"register-scheduledtask", r"currentversion\\run",
                    r"\bnew-service\b", r"__eventfilter", r"commandlineeventconsumer"],
    "credential": [r"mimikatz", r"sekurlsa", r"\blsass\b", r"logonpasswords"],
    "network_socket": [r"net\.sockets", r"tcpclient", r"tcplistener", r"\.getstream\(\)"],
    "reflection": [r"reflection\.assembly", r"\[system\.reflection", r"::load\(",
                   r"add-type"],
}
_COMPILED = {g: [re.compile(p) for p in pats] for g, pats in INDICATOR_GROUPS.items()}

_URL = re.compile(r"https?://[^\s'\"]+")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_B64 = re.compile(r"[a-z0-9+/]{80,}={0,2}", re.I)
_VAR = re.compile(r"\$[a-z_][a-z0-9_:]*")
_TOKEN = re.compile(r"[a-z0-9_\-\.]+")
_FUNC = re.compile(r"\bfunction\s+[a-z]")
_HELP = re.compile(r"\.(synopsis|description|example|parameter)\b")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


HANDCRAFTED_NAMES: list[str] = [
    "log_length", "log_lines", "mean_line_len", "log_max_line_len", "entropy",
    "ratio_alpha", "ratio_digit", "ratio_upper", "ratio_whitespace", "ratio_special",
    "ratio_backtick", "ratio_plus", "ratio_quote", "ratio_brace", "log_longest_token",
    "base64_blobs", "url_count", "ip_count", "var_density", "distinct_vars",
    "comment_ratio", "function_defs", "help_keywords", "has_param_block",
] + [f"ind_{g}" for g in INDICATOR_GROUPS]


def indicator_hits(norm_text: str) -> dict[str, int]:
    return {g: sum(len(p.findall(norm_text)) for p in pats) for g, pats in _COMPILED.items()}


def handcrafted_vector(text: str) -> np.ndarray:
    raw = text
    norm = normalise(text)
    n = max(len(raw), 1)
    lines = raw.splitlines() or [""]
    line_lens = [len(l) for l in lines]
    tokens = _TOKEN.findall(norm)
    longest = max((len(t) for t in tokens), default=0)
    comment_lines = sum(1 for l in lines if l.lstrip().startswith("#"))
    variables = _VAR.findall(norm)
    hits = indicator_hits(norm)
    feats = [
        math.log1p(len(raw)),
        math.log1p(len(lines)),
        float(np.mean(line_lens)),
        math.log1p(max(line_lens)),
        shannon_entropy(raw),
        sum(c.isalpha() for c in raw) / n,
        sum(c.isdigit() for c in raw) / n,
        sum(c.isupper() for c in raw) / n,
        sum(c.isspace() for c in raw) / n,
        sum((not c.isalnum()) and (not c.isspace()) for c in raw) / n,
        raw.count("`") / n,
        raw.count("+") / n,
        (raw.count("'") + raw.count('"')) / n,
        (raw.count("{") + raw.count("}")) / n,
        math.log1p(longest),
        float(len(_B64.findall(raw))),
        float(len(_URL.findall(norm))),
        float(len(_IP.findall(norm))),
        len(variables) / max(len(tokens), 1),
        float(len(set(variables))),
        comment_lines / len(lines),
        float(len(_FUNC.findall(norm))),
        float(len(_HELP.findall(norm))),
        float("param(" in norm.replace(" ", "")),
    ]
    feats += [math.log1p(hits[g]) for g in INDICATOR_GROUPS]
    return np.asarray(feats, dtype=np.float64)


class HandcraftedFeatures(BaseEstimator, TransformerMixin):
    """scikit-learn transformer wrapper around :func:`handcrafted_vector`."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.vstack([handcrafted_vector(t) for t in X])

    def get_feature_names_out(self, input_features=None):
        return np.asarray(HANDCRAFTED_NAMES)
