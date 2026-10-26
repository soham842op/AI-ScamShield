"""The synthetic evaluation set. Evaluation only, never training.

Rows in `synthetic/synthetic_eval_v1.jsonl`: `id`, `label` (`scam_like` or
`not_scam_like`), `category`, `text`. All names, numbers and domains are invented
(reserved example domains and drama-range phone numbers). `manifest.json` holds the
review status; results are reported as provisional until the set is approved.
"""

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sklearn.pipeline import Pipeline

from scamshield_ml.metrics import confusion, ranking
from scamshield_ml.prepare import model_input
from scamshield_ml.thresholds import Thresholds

SYNTHETIC_DIR = Path(__file__).resolve().parent.parent / "synthetic"
SET_PATH = SYNTHETIC_DIR / "synthetic_eval_v1.jsonl"
MANIFEST_PATH = SYNTHETIC_DIR / "manifest.json"
_LABELS = {"scam_like": 1, "not_scam_like": 0}


class SyntheticFormatError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SyntheticExample:
    id: str
    target: int
    category: str
    text: str


def load(path: Path = SET_PATH) -> list[SyntheticExample]:
    rows: list[SyntheticExample] = []
    seen: set[str] = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if set(row) != {"id", "label", "category", "text"}:
            raise SyntheticFormatError(f"line {number}: expected id, label, category, text")
        if row["label"] not in _LABELS or row["id"] in seen or not row["text"].strip():
            raise SyntheticFormatError(f"line {number}: bad label, duplicate id or empty text")
        seen.add(row["id"])
        rows.append(
            SyntheticExample(
                id=row["id"],
                target=_LABELS[row["label"]],
                category=row["category"],
                text=model_input(row["text"]),
            )
        )
    return rows


def status() -> str:
    if not MANIFEST_PATH.exists():
        return "missing"
    return str(json.loads(MANIFEST_PATH.read_text(encoding="utf-8")).get("status", "unknown"))


def evaluate(pipeline: Pipeline, thresholds: Thresholds) -> dict[str, Any] | None:
    if not SET_PATH.exists():
        return None
    examples = load()
    scores = [float(p) for p in pipeline.predict_proba([e.text for e in examples])[:, 1]]
    targets = [e.target for e in examples]
    per_category: dict[str, Counter[str]] = defaultdict(Counter)
    for example, score in zip(examples, scores, strict=True):
        counts = per_category[example.category]
        counts["total"] += 1
        counts["at_or_above_suspicious"] += score >= thresholds.suspicious
        counts["at_or_above_high_risk"] += score >= thresholds.high_risk
    return {
        "status": status(),
        "examples": len(examples),
        "positives": sum(targets),
        **ranking(targets, scores),
        "at_suspicious": confusion(targets, scores, thresholds.suspicious).summary(),
        "at_high_risk": confusion(targets, scores, thresholds.high_risk).summary(),
        "by_category": {
            name: {"label": _label_of(examples, name), **dict(counts)}
            for name, counts in sorted(per_category.items())
        },
    }


def _label_of(examples: list[SyntheticExample], category: str) -> str:
    targets = {e.target for e in examples if e.category == category}
    if targets == {1}:
        return "scam_like"
    if targets == {0}:
        return "not_scam_like"
    return "mixed"
