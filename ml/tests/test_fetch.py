import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from scamshield_ml import fetch
from scamshield_ml.sources import SOURCES, UCI, Source


def _source_for(path: Path, content: bytes) -> Source:
    return replace(UCI, size=len(content), sha256=hashlib.sha256(content).hexdigest())


def test_verify_accepts_matching_file(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(b"dataset bytes")
    fetch.verify(_source_for(path, b"dataset bytes"), path)


def test_verify_rejects_wrong_size(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(b"dataset bytes!")
    with pytest.raises(fetch.ChecksumError):
        fetch.verify(_source_for(path, b"dataset bytes"), path)


def test_verify_rejects_wrong_hash(tmp_path: Path) -> None:
    path = tmp_path / "a.zip"
    path.write_bytes(b"dataset bytez")
    with pytest.raises(fetch.ChecksumError):
        fetch.verify(_source_for(path, b"dataset bytes"), path)


def test_download_refuses_non_https(tmp_path: Path) -> None:
    source = replace(UCI, url="http://archive.example/data.zip")
    with pytest.raises(ValueError, match="https"):
        fetch._download(source, tmp_path / "x.zip")


def test_every_source_is_pinned() -> None:
    for source in SOURCES:
        assert source.url.startswith("https://")
        assert source.size > 0
        assert len(source.sha256) == 64
        assert source.member
