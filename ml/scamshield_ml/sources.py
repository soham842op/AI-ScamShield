"""The labeled datasets used for training and evaluation, both CC BY 4.0 (credits in the README).

Datasets are never committed. `fetch` downloads each archive from its official
page and refuses any file whose size or SHA-256 differs from the values pinned here.
"""

from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
RAW_DIR = DATA_DIR / "raw"


@dataclass(frozen=True, slots=True)
class Source:
    name: str
    url: str
    archive_name: str
    size: int
    sha256: str
    # The one archive member that holds the messages.
    member: str
    license: str
    citation: str
    page: str

    @property
    def directory(self) -> Path:
        return RAW_DIR / self.name

    @property
    def archive_path(self) -> Path:
        return self.directory / self.archive_name


UCI = Source(
    name="uci_sms_spam",
    url="https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
    archive_name="sms_spam_collection.zip",
    # UCI publishes no checksum; recorded on the first download (2026-10-21).
    size=203415,
    sha256="1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3",
    member="SMSSpamCollection",
    license="CC BY 4.0",
    citation=(
        "Almeida, T. & Hidalgo, J. (2011). SMS Spam Collection [Dataset]. "
        "UCI Machine Learning Repository. https://doi.org/10.24432/C5CC84"
    ),
    page="https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
)

MENDELEY = Source(
    name="mendeley_sms_phishing",
    url=(
        "https://data.mendeley.com/public-files/datasets/f45bkkt8pr/files/"
        "edb361de-918d-469f-9106-e84823830665/file_downloaded"
    ),
    archive_name="Dataset_5971.zip",
    # Size and SHA-256 as published by the Mendeley Data file listing.
    size=244698,
    sha256="9bbf3188fdad81495d8e82825648b9b63b53fc86841a3d26c02629990b233cc3",
    member="Dataset_5971.csv",
    license="CC BY 4.0",
    citation=(
        'Mishra, S. & Soni, D. (2022). "SMS PHISHING DATASET FOR MACHINE LEARNING AND '
        'PATTERN RECOGNITION", Mendeley Data, V1. https://doi.org/10.17632/f45bkkt8pr.1'
    ),
    page="https://data.mendeley.com/datasets/f45bkkt8pr/1",
)

SOURCES = (UCI, MENDELEY)
