"""Label mapping, deduplication and the train/validation/test split.

Label mapping: `spam` and `smishing` are `scam_like`
(target 1), `ham` is `not_scam_like` (target 0). Supplement rows arrive as `scam`
(target 1) or `ham`.

Most of the Mendeley set repeats UCI messages, so texts are deduplicated across
both datasets before splitting. The split is assigned per group of near-duplicates
(same text once punctuation is dropped and digit runs are masked), so a template
that differs only in a phone number or amount never lands in two splits.
"""

import hashlib
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from scamshield_ml.load import RawExample, SourceLabel

Split = Literal["train", "validation", "test"]
SPLITS: tuple[Split, ...] = ("train", "validation", "test")
SPLIT_SEED = "scamshield-cp5-v1"
TRAIN_FRACTION = 0.70
VALIDATION_FRACTION = 0.15

TARGETS: dict[SourceLabel, int] = {"ham": 0, "spam": 1, "smishing": 1, "scam": 1}
# When duplicates carry different (but same-target) labels, report the most specific.
_LABEL_RANK: dict[SourceLabel, int] = {"smishing": 0, "scam": 1, "spam": 2, "ham": 3}

_PUNCTUATION = re.compile(r"[^\w\s]")
_DIGITS = re.compile(r"\d+")


def model_input(text: str) -> str:
    """The text the model sees. Same as `normalize(text).features` in the backend:
    NFC, then NFKC, then invisible format characters (category Cf) removed."""
    folded = unicodedata.normalize("NFKC", unicodedata.normalize("NFC", text))
    return "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")


def dedup_key(text: str) -> str:
    return " ".join(model_input(text).casefold().split())


def group_key(text: str) -> str:
    return " ".join(_DIGITS.sub("0", _PUNCTUATION.sub(" ", dedup_key(text))).split())


def assign_split(group: str, seed: str = SPLIT_SEED) -> Split:
    digest = hashlib.sha256(f"{seed}\x00{group}".encode()).digest()
    position = int.from_bytes(digest[:8], "big") / 2**64
    if position < TRAIN_FRACTION:
        return "train"
    if position < TRAIN_FRACTION + VALIDATION_FRACTION:
        return "validation"
    return "test"


@dataclass(frozen=True, slots=True)
class Example:
    text: str
    target: int
    source_label: SourceLabel
    datasets: frozenset[str]
    group: str


@dataclass(slots=True)
class PrepareStats:
    raw_rows: Counter[str] = field(default_factory=Counter)
    empty_dropped: int = 0
    duplicates_merged: int = 0
    conflicts_dropped: int = 0
    unique_texts: int = 0
    in_both_datasets: int = 0
    groups: int = 0


def prepare(raw: Iterable[RawExample]) -> tuple[list[Example], PrepareStats]:
    stats = PrepareStats()
    by_key: dict[str, list[RawExample]] = defaultdict(list)
    for row in raw:
        stats.raw_rows[row.dataset] += 1
        key = dedup_key(row.text)
        if not key:
            stats.empty_dropped += 1
            continue
        by_key[key].append(row)

    examples: list[Example] = []
    for key in sorted(by_key):
        rows = by_key[key]
        stats.duplicates_merged += len(rows) - 1
        targets = {TARGETS[r.source_label] for r in rows}
        if len(targets) > 1:
            stats.conflicts_dropped += 1
            continue
        label = min((r.source_label for r in rows), key=_LABEL_RANK.__getitem__)
        datasets = frozenset(r.dataset for r in rows)
        if len(datasets) > 1:
            stats.in_both_datasets += 1
        examples.append(
            Example(
                # The first spelling seen, in model-input form.
                text=model_input(rows[0].text),
                target=targets.pop(),
                source_label=label,
                datasets=datasets,
                group=group_key(key),
            )
        )
    stats.unique_texts = len(examples)
    stats.groups = len({e.group for e in examples})
    return examples, stats


def split(examples: Iterable[Example], seed: str = SPLIT_SEED) -> dict[Split, list[Example]]:
    parts: dict[Split, list[Example]] = {name: [] for name in SPLITS}
    for example in examples:
        parts[assign_split(example.group, seed)].append(example)
    return parts
