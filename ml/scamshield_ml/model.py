"""The baseline model: TF-IDF features and logistic regression.

Only standard scikit-learn classes go into the pipeline, so the backend can load
it without importing this package.
"""

from dataclasses import dataclass

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

MODEL_NAME = "tfidf-logreg"
RANDOM_STATE = 0


@dataclass(frozen=True, slots=True)
class Candidate:
    features: str  # "word" or "word+char"
    c: float
    # Training weight of each current-style supplement row (public rows weigh 1).
    supplement_weight: float = 1.0

    @property
    def name(self) -> str:
        return f"{self.features}/C={self.c:g}/w={self.supplement_weight:g}"


# Compared on the validation split only. The test split is never used to choose.
CANDIDATES: tuple[Candidate, ...] = tuple(
    Candidate(features=f, c=c, supplement_weight=w)
    for f in ("word", "word+char")
    for c in (0.5, 1, 2, 4, 8, 16)
    for w in (1.0, 3.0, 5.0)
)


def _word() -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True, dtype=np.float64
    )


def _char() -> TfidfVectorizer:
    return TfidfVectorizer(
        lowercase=True,
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        sublinear_tf=True,
        dtype=np.float64,
    )


def build(candidate: Candidate) -> Pipeline:
    if candidate.features == "word":
        features: TfidfVectorizer | FeatureUnion = _word()
    elif candidate.features == "word+char":
        features = FeatureUnion([("word", _word()), ("char", _char())])
    else:
        raise ValueError(f"unknown feature set {candidate.features}")
    classifier = LogisticRegression(
        C=candidate.c, class_weight="balanced", max_iter=5000, random_state=RANDOM_STATE
    )
    return Pipeline([("features", features), ("classifier", classifier)])
