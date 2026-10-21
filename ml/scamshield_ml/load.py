"""Read the labeled messages from the verified archives.

Message text is held in memory only. Nothing here writes or prints it.
"""

import csv
import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from scamshield_ml.fetch import verify
from scamshield_ml.sources import MENDELEY, UCI, Source

# `scam` comes only from the current-style supplement.
SourceLabel = Literal["ham", "spam", "smishing", "scam"]
# Labels the public files may contain.
_LABELS: frozenset[str] = frozenset(("ham", "spam", "smishing"))
# Both archives hold well under a megabyte of text; anything larger is not the pinned file.
MAX_MEMBER_BYTES = 5_000_000


class DatasetFormatError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class RawExample:
    dataset: str
    source_label: SourceLabel
    text: str


def _label(value: str, source: Source) -> SourceLabel:
    label = value.strip().lower()
    if label not in _LABELS:
        raise DatasetFormatError(f"{source.name}: unknown label")
    return label  # type: ignore[return-value]


def _member_text(source: Source) -> str:
    verify(source, source.archive_path)
    with zipfile.ZipFile(source.archive_path) as archive:
        info = archive.getinfo(source.member)
        if info.file_size > MAX_MEMBER_BYTES:
            raise DatasetFormatError(f"{source.name}: member larger than expected")
        return archive.read(info).decode("utf-8")


def read_uci() -> Iterator[RawExample]:
    """`SMSSpamCollection`: one message per line, `label<TAB>text`."""
    for line in _member_text(UCI).splitlines():
        label, sep, text = line.partition("\t")
        if not sep:
            raise DatasetFormatError(f"{UCI.name}: line without a tab")
        yield RawExample(dataset=UCI.name, source_label=_label(label, UCI), text=text)


def read_mendeley() -> Iterator[RawExample]:
    """`Dataset_5971.csv`: header LABEL, TEXT, URL, EMAIL, PHONE. Labels vary in case."""
    rows = csv.reader(io.StringIO(_member_text(MENDELEY), newline=""))
    header = next(rows)
    if header[:2] != ["LABEL", "TEXT"]:
        raise DatasetFormatError(f"{MENDELEY.name}: unexpected header")
    for row in rows:
        if len(row) < 2:
            raise DatasetFormatError(f"{MENDELEY.name}: short row")
        yield RawExample(dataset=MENDELEY.name, source_label=_label(row[0], MENDELEY), text=row[1])


def read_all() -> list[RawExample]:
    return [*read_uci(), *read_mendeley()]
