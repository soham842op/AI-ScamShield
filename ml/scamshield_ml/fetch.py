"""Download the dataset archives and verify them against the pinned size and SHA-256.

Usage, from `ml/`:  uv run python -m scamshield_ml.fetch

Archives are kept as downloaded and never extracted to disk; `load` reads the one
expected member straight from the verified archive.
"""

import hashlib
import hmac
import sys
import urllib.request
from pathlib import Path

from scamshield_ml.sources import SOURCES, Source

TIMEOUT_SECONDS = 60
CHUNK = 64 * 1024


class ChecksumError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(source: Source, path: Path) -> None:
    size = path.stat().st_size
    if size != source.size:
        raise ChecksumError(f"{source.name}: size {size} != pinned {source.size}")
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, source.sha256):
        raise ChecksumError(f"{source.name}: sha256 {actual} != pinned {source.sha256}")


def _download(source: Source, target: Path) -> None:
    if not source.url.startswith("https://"):
        raise ValueError(f"{source.name}: only https sources are allowed")
    request = urllib.request.Request(source.url, headers={"User-Agent": "scamshield-ml-fetch"})  # noqa: S310
    partial = target.with_suffix(target.suffix + ".part")
    received = 0
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        with partial.open("wb") as out:
            while block := response.read(CHUNK):
                received += len(block)
                # Stop early instead of filling the disk on a wrong or hostile response.
                if received > source.size:
                    raise ChecksumError(f"{source.name}: response larger than pinned size")
                out.write(block)
    partial.replace(target)


def fetch(source: Source) -> Path:
    path = source.archive_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            verify(source, path)
            return path
        except ChecksumError:
            path.unlink()
    _download(source, path)
    try:
        verify(source, path)
    except ChecksumError:
        path.unlink()
        raise
    return path


def main() -> int:
    for source in SOURCES:
        try:
            path = fetch(source)
        except (ChecksumError, OSError) as exc:
            print(f"FAILED {source.name}: {exc}", file=sys.stderr)
            return 1
        print(f"ok {source.name} {source.sha256} {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
