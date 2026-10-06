"""Model definitions. Every model is a scikit-learn Pipeline that takes raw
script text, so training, cross-validation and deployment share one code path."""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FunctionTransformer, Pipeline
from sklearn.preprocessing import StandardScaler

from .features import HandcraftedFeatures, normalise

SEED = 42


def _normalise_all(X):
    return [normalise(t) for t in X]


def char_tfidf() -> TfidfVectorizer:
    # Character 3-5 grams survive renamed variables and partial string splitting
    # better than word tokens; sublinear tf damps very long scripts.
    return TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=3,
                           max_features=50_000, sublinear_tf=True, dtype=np.float32)


def tfidf_lr() -> Pipeline:
    return Pipeline([
        ("norm", FunctionTransformer(_normalise_all)),
        ("tfidf", char_tfidf()),
        ("clf", LogisticRegression(C=10.0, max_iter=2000, class_weight="balanced")),
    ])


def handcrafted_rf() -> Pipeline:
    return Pipeline([
        ("feat", HandcraftedFeatures()),
        ("clf", RandomForestClassifier(n_estimators=300, min_samples_leaf=1,
                                       class_weight="balanced", n_jobs=-1,
                                       random_state=SEED)),
    ])


def handcrafted_gb() -> Pipeline:
    return Pipeline([
        ("feat", HandcraftedFeatures()),
        ("clf", HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08,
                                               class_weight="balanced",
                                               random_state=SEED)),
    ])


def handcrafted_lr() -> Pipeline:
    return Pipeline([
        ("feat", HandcraftedFeatures()),
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])


MODEL_FACTORIES = {
    "Handcrafted + LR": handcrafted_lr,
    "Handcrafted + RF": handcrafted_rf,
    "Handcrafted + HGB": handcrafted_gb,
    "Char TF-IDF + LR": tfidf_lr,
}


class SoftVotingEnsemble:
    """Averages the malicious-class probabilities of a lexical model (char
    TF-IDF + LR) and a behavioural model (hand-crafted + RF). The two views
    fail on different inputs, so the average is more stable than either."""

    def __init__(self, weights=(0.5, 0.5)):
        self.weights = weights
        self.members = [tfidf_lr(), handcrafted_rf()]

    def fit(self, X, y):
        for m in self.members:
            m.fit(X, y)
        return self

    def predict_proba(self, X):
        p = sum(w * m.predict_proba(X)[:, 1] for w, m in zip(self.weights, self.members))
        return np.column_stack([1 - p, p])

    def predict(self, X, threshold=0.5):
        return (self.predict_proba(X)[:, 1] >= threshold).astype(int)
