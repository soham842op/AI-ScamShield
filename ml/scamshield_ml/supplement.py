"""Owner-approved current-style training supplement (ADR 011 amendment, 2026-10-21).

`supplement/current_style_train_v1.jsonl` uses the same row format as the synthetic
evaluation set: `id`, `label` (`scam_like` or `not_scam_like`), `category`, `text`.
All names, brands, numbers and domains are invented. It goes through the same
deduplication and split as the public datasets, so part of it lands in validation
and test. It must never share a message with the synthetic evaluation set; `train`
stops if any evaluation message is a near-copy of a supplement message.
"""

import hashlib
import json
from pathlib import Path

from scamshield_ml.load import RawExample

DATASET = "current_style_supplement"
SUPPLEMENT_DIR = Path(__file__).resolve().parent.parent / "supplement"
SET_PATH = SUPPLEMENT_DIR / "current_style_train_v1.jsonl"
MANIFEST_PATH = SUPPLEMENT_DIR / "manifest.json"
_LABELS = {"scam_like": "scam", "not_scam_like": "ham"}


class SupplementFormatError(Exception):
    pass


def sha256() -> str:
    return hashlib.sha256(SET_PATH.read_bytes()).hexdigest()


def status() -> str:
    if not MANIFEST_PATH.exists():
        return "missing"
    return str(json.loads(MANIFEST_PATH.read_text(encoding="utf-8")).get("status", "unknown"))


def read(path: Path = SET_PATH) -> list[RawExample]:
    rows: list[RawExample] = []
    seen: set[str] = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if set(row) != {"id", "label", "category", "text"}:
            raise SupplementFormatError(f"line {number}: expected id, label, category, text")
        if row["label"] not in _LABELS or row["id"] in seen or not row["text"].strip():
            raise SupplementFormatError(f"line {number}: bad label, duplicate id or empty text")
        seen.add(row["id"])
        rows.append(
            RawExample(dataset=DATASET, source_label=_LABELS[row["label"]], text=row["text"])  # type: ignore[arg-type]
        )
    return rows
