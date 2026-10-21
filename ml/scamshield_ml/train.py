"""Train, choose thresholds and evaluate the baseline classifier.

Usage, from `ml/` after `python -m scamshield_ml.fetch`:

    uv run python -m scamshield_ml.train --skip-test   # development: validation only
    uv run python -m scamshield_ml.train               # final run: also scores the test split
    uv run python -m scamshield_ml.train --compare artifacts/tfidf-logreg-1.0.0/model.joblib

Model and threshold choices use the validation split only. The test split and the
synthetic set are scored once, after everything is fixed, and nothing is chosen from
them. The report holds
counts and metrics only, never message text.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.pipeline import Pipeline

from scamshield_ml import artifact, supplement, synthetic
from scamshield_ml.load import read_all
from scamshield_ml.metrics import confusion, ranking
from scamshield_ml.model import CANDIDATES, MODEL_NAME, Candidate, build
from scamshield_ml.prepare import SPLIT_SEED, SPLITS, Example, Split, prepare, split
from scamshield_ml.sources import SOURCES
from scamshield_ml.thresholds import (
    HIGH_RISK_MIN_PRECISION,
    SUSPICIOUS_MIN_RECALL,
    Thresholds,
    choose,
)

MODEL_VERSION = "1.1.0"
REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"
# A synthetic evaluation message this similar to a supplement message counts as a copy.
EVAL_COPY_SIMILARITY = 0.8
REFERENCE_THRESHOLDS = (0.3, 0.5, 0.7, 0.9)

_URL = re.compile(r"https?://|www\.|\b[a-z0-9-]+\.(?:com|net|org|co|uk|info|biz|ly)\b", re.I)
_LONG_NUMBER = re.compile(r"\d{5,}")


def _scores(pipeline: Pipeline, examples: Sequence[Example]) -> list[float]:
    return [float(p) for p in pipeline.predict_proba([e.text for e in examples])[:, 1]]


def _targets(examples: Sequence[Example]) -> list[int]:
    return [e.target for e in examples]


def _length_bucket(text: str) -> str:
    if len(text) < 50:
        return "under_50"
    if len(text) <= 160:
        return "50_to_160"
    return "over_160"


def _origin(example: Example) -> str:
    return "both" if len(example.datasets) > 1 else next(iter(example.datasets))


def error_analysis(
    examples: Sequence[Example], scores: Sequence[float], threshold: float
) -> dict[str, Any]:
    """Where the errors fall, as counts by coarse traits. No text."""
    errors: dict[str, Counter[str]] = {"false_negative": Counter(), "false_positive": Counter()}
    totals: Counter[str] = Counter()
    for example, score in zip(examples, scores, strict=True):
        traits = [
            f"label:{example.source_label}",
            f"origin:{_origin(example)}",
            f"length:{_length_bucket(example.text)}",
            f"has_link:{bool(_URL.search(example.text))}",
            f"has_long_number:{bool(_LONG_NUMBER.search(example.text))}",
        ]
        totals.update(traits)
        predicted = score >= threshold
        if predicted == bool(example.target):
            continue
        kind = "false_positive" if predicted else "false_negative"
        errors[kind].update(traits)
    return {
        "threshold": threshold,
        "false_negative_by_trait": dict(sorted(errors["false_negative"].items())),
        "false_positive_by_trait": dict(sorted(errors["false_positive"].items())),
        "examples_by_trait": dict(sorted(totals.items())),
    }


def _recall_by_label(
    examples: Sequence[Example], scores: Sequence[float], threshold: float
) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for label in ("spam", "smishing", "scam"):
        hits = [
            s >= threshold for e, s in zip(examples, scores, strict=True) if e.source_label == label
        ]
        out[label] = {"detected": sum(hits), "total": len(hits)}
    return out


def _is_supplement(example: Example) -> bool:
    return supplement.DATASET in example.datasets


def evaluate(
    examples: Sequence[Example], scores: Sequence[float], thresholds: Thresholds
) -> dict[str, Any]:
    """Metrics for all examples, then separately for public-dataset and supplement rows."""
    result = _metrics(examples, scores, thresholds)
    by_origin: dict[str, Any] = {}
    for name, wanted in (("public", False), ("supplement", True)):
        subset = [
            (e, s) for e, s in zip(examples, scores, strict=True) if _is_supplement(e) == wanted
        ]
        if subset:
            by_origin[name] = _metrics([e for e, _ in subset], [s for _, s in subset], thresholds)
    result["by_origin"] = by_origin
    return result


def _metrics(
    examples: Sequence[Example], scores: Sequence[float], thresholds: Thresholds
) -> dict[str, Any]:
    targets = _targets(examples)
    return {
        "examples": len(examples),
        "positives": sum(targets),
        **ranking(targets, scores),
        "at_suspicious": confusion(targets, scores, thresholds.suspicious).summary(),
        "at_high_risk": confusion(targets, scores, thresholds.high_risk).summary(),
        "reference": {
            str(t): confusion(targets, scores, t).summary() for t in REFERENCE_THRESHOLDS
        },
        "recall_by_source_label_at_suspicious": _recall_by_label(
            examples, scores, thresholds.suspicious
        ),
        "recall_by_source_label_at_high_risk": _recall_by_label(
            examples, scores, thresholds.high_risk
        ),
        "error_analysis_at_suspicious": error_analysis(examples, scores, thresholds.suspicious),
    }


def _split_summary(parts: Mapping[Split, list[Example]]) -> dict[str, Any]:
    return {
        name: {
            "examples": len(items),
            "groups": len({e.group for e in items}),
            "by_source_label": dict(sorted(Counter(e.source_label for e in items).items())),
        }
        for name, items in parts.items()
    }


def _leakage_check(parts: Mapping[Split, list[Example]]) -> dict[str, int]:
    """Texts and near-duplicate groups shared between splits. Must all be zero."""
    out: dict[str, int] = {}
    for i, a in enumerate(SPLITS):
        for b in SPLITS[i + 1 :]:
            out[f"texts_{a}_{b}"] = len(
                {e.text.casefold() for e in parts[a]} & {e.text.casefold() for e in parts[b]}
            )
            out[f"groups_{a}_{b}"] = len({e.group for e in parts[a]} & {e.group for e in parts[b]})
    return out


def fit(candidate: Candidate, train: Sequence[Example]) -> Pipeline:
    weights = [candidate.supplement_weight if _is_supplement(e) else 1.0 for e in train]
    return build(candidate).fit(
        [e.text for e in train], _targets(train), classifier__sample_weight=weights
    )


def _origin_ap(
    examples: Sequence[Example], scores: Sequence[float], supplement_rows: bool
) -> float:
    pairs = [
        (e.target, s)
        for e, s in zip(examples, scores, strict=True)
        if _is_supplement(e) == supplement_rows
    ]
    value = ranking([t for t, _ in pairs], [s for _, s in pairs])["average_precision"]
    return float(value or 0.0)


def select(
    train: Sequence[Example], validation: Sequence[Example]
) -> tuple[Candidate, list[dict[str, Any]]]:
    """Pick the candidate with the best validation score.

    The score is the mean of the average precision on public-dataset rows and on
    supplement rows, so the small current-style part counts as much as the large
    public part. Ties within 0.001 go to the simpler feature set, then the smaller C,
    then the smaller supplement weight."""
    results: list[dict[str, Any]] = []
    for candidate in CANDIDATES:
        scores = _scores(fit(candidate, train), validation)
        public = _origin_ap(validation, scores, supplement_rows=False)
        current = _origin_ap(validation, scores, supplement_rows=True)
        results.append(
            {
                "candidate": candidate.name,
                "score": (public + current) / 2,
                "average_precision_public": public,
                "average_precision_supplement": current,
                **ranking(_targets(validation), scores),
            }
        )
    best = max(float(r["score"]) for r in results)
    eligible = [
        c for c, r in zip(CANDIDATES, results, strict=True) if float(r["score"]) >= best - 0.001
    ]
    chosen = min(eligible, key=lambda c: (c.features != "word", c.c, c.supplement_weight))
    return chosen, results


def synthetic_overlap(examples: Sequence[Example]) -> dict[str, Any]:
    """How close the synthetic evaluation set comes to any supplement message.

    Character n-gram TF-IDF cosine similarity; no text is reported."""
    supplement_texts = [e.text for e in examples if _is_supplement(e)]
    if not supplement_texts or not synthetic.SET_PATH.exists():
        return {"max_similarity": None, "copies": 0}
    eval_texts = [e.text for e in synthetic.load()]
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit(
        supplement_texts + eval_texts
    )
    similarity = cosine_similarity(
        vectorizer.transform(eval_texts), vectorizer.transform(supplement_texts)
    ).max(axis=1)
    return {
        "max_similarity": round(float(similarity.max()), 4),
        "copies": int((similarity >= EVAL_COPY_SIMILARITY).sum()),
    }


def _compare(
    path: Path, parts: Mapping[Split, list[Example]], *, score_test: bool
) -> dict[str, Any]:
    """Score an earlier artifact (our own local file) on the same splits with its own
    thresholds, so the two models are compared on identical messages."""
    content = joblib.load(path)
    thresholds = Thresholds(**content["thresholds"])
    old: Pipeline = content["pipeline"]
    out: dict[str, Any] = {
        "model_version": content["model_version"],
        "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "thresholds": content["thresholds"],
        "validation": evaluate(parts["validation"], _scores(old, parts["validation"]), thresholds),
        "test": None,
        "synthetic": None,
    }
    if score_test:
        out["test"] = evaluate(parts["test"], _scores(old, parts["test"]), thresholds)
        out["synthetic"] = synthetic.evaluate(old, thresholds)
    return out


def run(*, score_test: bool, compare: Path | None = None) -> dict[str, Any]:
    examples, stats = prepare([*read_all(), *supplement.read()])
    parts = split(examples)
    leakage = _leakage_check(parts)
    if any(leakage.values()):
        raise RuntimeError(f"split leakage: {leakage}")
    overlap = synthetic_overlap(examples)
    if overlap["copies"]:
        raise RuntimeError(f"synthetic evaluation messages copied in the supplement: {overlap}")

    chosen, candidates = select(parts["train"], parts["validation"])
    pipeline = fit(chosen, parts["train"])
    validation_scores = _scores(pipeline, parts["validation"])
    thresholds = choose(_targets(parts["validation"]), validation_scores)

    content = artifact.bundle(
        pipeline,
        thresholds,
        model_version=f"{MODEL_NAME}-{MODEL_VERSION}",
        data_sha256={
            **{s.name: s.sha256 for s in SOURCES},
            supplement.DATASET: supplement.sha256(),
        },
        split_seed=SPLIT_SEED,
    )
    artifact_sha256 = artifact.save(content)
    # A versioned copy, so a later run can be compared with this one.
    artifact.save(content, artifact.ARTIFACTS_DIR / content["model_version"] / "model.joblib")

    report: dict[str, Any] = {
        "model_version": content["model_version"],
        "sklearn_version": content["sklearn_version"],
        "artifact_sha256": artifact_sha256,
        "data_sha256": content["data_sha256"],
        "split_seed": SPLIT_SEED,
        "label_mapping": {
            "ham": "not_scam_like",
            "spam": "scam_like",
            "smishing": "scam_like",
            "scam (supplement)": "scam_like",
        },
        "supplement_status": supplement.status(),
        "synthetic_overlap": overlap,
        "preparation": {
            "raw_rows": dict(stats.raw_rows),
            "empty_dropped": stats.empty_dropped,
            "duplicates_merged": stats.duplicates_merged,
            "conflicts_dropped": stats.conflicts_dropped,
            "unique_texts": stats.unique_texts,
            "in_both_datasets": stats.in_both_datasets,
            "near_duplicate_groups": stats.groups,
        },
        "splits": _split_summary(parts),
        "leakage_check": leakage,
        "candidates_on_validation": candidates,
        "chosen_candidate": chosen.name,
        "threshold_rule": {
            "high_risk_min_validation_precision": HIGH_RISK_MIN_PRECISION,
            "suspicious_min_validation_recall": SUSPICIOUS_MIN_RECALL,
        },
        "thresholds": content["thresholds"],
        "validation": evaluate(parts["validation"], validation_scores, thresholds),
        "test": None,
        "synthetic": None,
        "comparison": None,
    }
    if score_test:
        test_scores = _scores(pipeline, parts["test"])
        report["test"] = evaluate(parts["test"], test_scores, thresholds)
        # Held out like the test split: scored only in the final run.
        report["synthetic"] = synthetic.evaluate(pipeline, thresholds)
    if compare is not None:
        report["comparison"] = _compare(compare, parts, score_test=score_test)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-test", action="store_true", help="do not score the test split")
    parser.add_argument("--compare", type=Path, help="earlier artifact to score on the same splits")
    args = parser.parse_args(argv)
    report = run(score_test=not args.skip_test, compare=args.compare)
    path = REPORT_DIR / f"metrics_{report['model_version']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"model {report['model_version']} sha256 {report['artifact_sha256']}")
    print(f"thresholds {report['thresholds']}")
    print(f"report {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
