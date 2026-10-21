"""Baseline text classifier: artifact loading and scoring.

The artifact is a joblib (pickle) file written by `ml/`. Unpickling runs code, so its
SHA-256 is compared with MODEL_ARTIFACT_SHA256 first, and the bytes that were hashed
are the bytes that are loaded. Any failure leaves the classifier unavailable; the
analysis still completes on rules and URL checks.
"""

import hashlib
import hmac
import io
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import joblib
import sklearn
from starlette.concurrency import run_in_threadpool

from app.pipeline.aggregator import Thresholds
from app.pipeline.types import ClassifierLabel, ClassifierResult

__all__ = [
    "LoadedClassifier",
    "TextClassifier",
    "load_classifier",
    "run_classifier",
]

ARTIFACT_FORMAT = "scamshield-text-classifier"
FORMAT_VERSION = 1
# The v1 artifact is a few megabytes; anything far larger is not ours.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_log = logging.getLogger(__name__)


class TextClassifier(Protocol):
    @property
    def version(self) -> str: ...

    @property
    def thresholds(self) -> Thresholds: ...

    def score(self, text: str) -> float: ...


class ArtifactError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class LoadedClassifier:
    version: str
    thresholds: Thresholds
    pipeline: Any

    def score(self, text: str) -> float:
        value = float(self.pipeline.predict_proba([text])[0, 1])
        if not (math.isfinite(value) and 0.0 <= value <= 1.0):
            raise ValueError("score outside 0..1")
        return value


def _read(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ArtifactError("artifact larger than the size limit")
    return data


def _from_bundle(content: Any) -> LoadedClassifier:
    if not isinstance(content, dict):
        raise ArtifactError("artifact is not a bundle")
    if content.get("format") != ARTIFACT_FORMAT or content.get("format_version") != FORMAT_VERSION:
        raise ArtifactError("unsupported artifact format")
    if content.get("sklearn_version") != sklearn.__version__:
        raise ArtifactError("artifact was built with a different scikit-learn version")
    version = content.get("model_version")
    if not isinstance(version, str) or not version:
        raise ArtifactError("artifact has no model version")
    raw = content.get("thresholds")
    if not isinstance(raw, dict):
        raise ArtifactError("artifact has no thresholds")
    thresholds = Thresholds(suspicious=float(raw["suspicious"]), high_risk=float(raw["high_risk"]))
    pipeline = content.get("pipeline")
    if not callable(getattr(pipeline, "predict_proba", None)):
        raise ArtifactError("artifact has no usable pipeline")
    return LoadedClassifier(version=version, thresholds=thresholds, pipeline=pipeline)


def load_classifier(path: str, expected_sha256: str) -> LoadedClassifier | None:
    """Load and verify the artifact. Returns None, and never raises, when it cannot."""
    expected = expected_sha256.strip().lower()
    if not expected:
        _log.info("model artifact not configured")
        return None
    if not _SHA256_HEX.fullmatch(expected):
        _log.error("MODEL_ARTIFACT_SHA256 is not a SHA-256 hex digest")
        return None
    try:
        data = _read(Path(path))
    except FileNotFoundError:
        _log.error("model artifact not found")
        return None
    except (OSError, ArtifactError) as exc:
        _log.error("model artifact could not be read type=%s", type(exc).__name__)
        return None
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected):
        _log.error("model artifact checksum mismatch")
        return None
    try:
        classifier = _from_bundle(joblib.load(io.BytesIO(data)))
    except Exception as exc:
        _log.error("model artifact could not be loaded type=%s", type(exc).__name__)
        return None
    _log.info("model artifact loaded version=%s", classifier.version)
    return classifier


async def run_classifier(classifier: TextClassifier | None, text: str) -> ClassifierResult:
    """Score `text` off the event loop. A failure is `unavailable`, never an exception.

    `label` is `scam_like` iff the score reaches the suspicious threshold T_s, the same
    cut that emits the `classifier_scam_like` signal. The score is not rounded, so
    every comparison here matches the one made when the thresholds were chosen.
    """
    if classifier is None:
        return ClassifierResult(status="unavailable")
    try:
        raw = float(await run_in_threadpool(classifier.score, text))
        if not (math.isfinite(raw) and 0.0 <= raw <= 1.0):
            raise ValueError("score outside 0..1")
    except Exception as exc:
        # Type only: the message could carry submitted text.
        _log.warning("classifier failed: %s", type(exc).__name__)
        return ClassifierResult(status="unavailable")
    label: ClassifierLabel = (
        "scam_like" if raw >= classifier.thresholds.suspicious else "not_scam_like"
    )
    return ClassifierResult(status="ok", label=label, raw_score=raw)
