import hashlib
import logging
import threading
import unicodedata
from pathlib import Path
from typing import Any

import joblib
import pytest
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.pipeline import classifier as clf
from app.pipeline.aggregator import Thresholds
from app.pipeline.normalize import normalize

_TEXTS = ["win a prize now", "claim your reward today", "see you at lunch", "meeting at 3"] * 3
_TARGETS = [1, 1, 0, 0] * 3
SECRET = "canary-text-7f3a"  # noqa: S105


def _bundle(**overrides: Any) -> dict[str, Any]:
    pipeline = Pipeline(
        [("features", TfidfVectorizer()), ("classifier", LogisticRegression())]
    ).fit(_TEXTS, _TARGETS)
    content: dict[str, Any] = {
        "format": clf.ARTIFACT_FORMAT,
        "format_version": clf.FORMAT_VERSION,
        "model_version": "tfidf-logreg-test",
        "sklearn_version": sklearn.__version__,
        "thresholds": {"suspicious": 0.3, "high_risk": 0.7},
        "data_sha256": {},
        "split_seed": "test",
        "pipeline": pipeline,
    }
    content.update(overrides)
    return content


def _write(tmp_path: Path, content: Any) -> tuple[str, str]:
    path = tmp_path / "model.joblib"
    joblib.dump(content, path)
    return str(path), hashlib.sha256(path.read_bytes()).hexdigest()


class FixedClassifier:
    def __init__(self, value: Any = 0.5, error: Exception | None = None) -> None:
        self.version = "fixed-1"
        self.thresholds = Thresholds(suspicious=0.3, high_risk=0.7)
        self.value = value
        self.error = error
        self.seen: list[str] = []
        self.thread: int | None = None

    def score(self, text: str) -> float:
        self.seen.append(text)
        self.thread = threading.get_ident()
        if self.error is not None:
            raise self.error
        return self.value  # type: ignore[no-any-return]


def test_loads_verified_artifact(tmp_path: Path) -> None:
    path, digest = _write(tmp_path, _bundle())
    loaded = clf.load_classifier(path, digest.upper())
    assert loaded is not None
    assert loaded.version == "tfidf-logreg-test"
    assert loaded.thresholds == Thresholds(suspicious=0.3, high_risk=0.7)
    assert 0.0 <= loaded.score("claim your prize") <= 1.0


def test_not_configured_returns_none(tmp_path: Path) -> None:
    path, _ = _write(tmp_path, _bundle())
    assert clf.load_classifier(path, "") is None


@pytest.mark.parametrize("value", ["abc", "0" * 63, "g" * 64])
def test_malformed_checksum_returns_none(tmp_path: Path, value: str) -> None:
    path, _ = _write(tmp_path, _bundle())
    assert clf.load_classifier(path, value) is None


def test_missing_file_returns_none(tmp_path: Path) -> None:
    assert clf.load_classifier(str(tmp_path / "absent.joblib"), "0" * 64) is None


def test_checksum_mismatch_never_unpickles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    path, _ = _write(tmp_path, _bundle())

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("joblib.load must not run on an unverified file")

    monkeypatch.setattr(clf.joblib, "load", forbidden)
    with caplog.at_level(logging.ERROR):
        assert clf.load_classifier(path, "0" * 64) is None
    assert "checksum mismatch" in caplog.text


def test_oversized_artifact_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, digest = _write(tmp_path, _bundle())
    monkeypatch.setattr(clf, "MAX_ARTIFACT_BYTES", 10)
    assert clf.load_classifier(path, digest) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"format": "something-else"},
        {"format_version": 2},
        {"sklearn_version": "0.0.1"},
        {"model_version": ""},
        {"thresholds": {"suspicious": 0.8, "high_risk": 0.7}},
        {"pipeline": object()},
    ],
)
def test_invalid_bundles_return_none(tmp_path: Path, overrides: dict[str, Any]) -> None:
    path, digest = _write(tmp_path, _bundle(**overrides))
    assert clf.load_classifier(path, digest) is None


def test_non_bundle_returns_none(tmp_path: Path) -> None:
    path, digest = _write(tmp_path, ["not", "a", "bundle"])
    assert clf.load_classifier(path, digest) is None


@pytest.mark.anyio
async def test_no_classifier_is_unavailable() -> None:
    result = await clf.run_classifier(None, "text")
    assert (result.status, result.label, result.raw_score) == ("unavailable", None, None)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("value", "label"),
    [(0.29999, "not_scam_like"), (0.3, "scam_like"), (0.91234567, "scam_like")],
)
async def test_label_follows_suspicious_threshold(value: float, label: str) -> None:
    result = await clf.run_classifier(FixedClassifier(value), "text")
    assert result.status == "ok"
    assert result.label == label
    assert result.raw_score == value


@pytest.mark.anyio
async def test_scoring_runs_off_the_event_loop_thread() -> None:
    model = FixedClassifier(0.5)
    await clf.run_classifier(model, "text")
    assert model.thread is not None
    assert model.thread != threading.get_ident()


@pytest.mark.anyio
@pytest.mark.parametrize("value", [float("nan"), 1.5, -0.1, "x"])
async def test_bad_scores_are_unavailable(value: Any) -> None:
    result = await clf.run_classifier(FixedClassifier(value), "text")
    assert result.status == "unavailable"


@pytest.mark.anyio
async def test_failure_is_unavailable_and_logs_no_text(caplog: pytest.LogCaptureFixture) -> None:
    model = FixedClassifier(error=RuntimeError(SECRET))
    with caplog.at_level(logging.DEBUG):
        result = await clf.run_classifier(model, SECRET)
    assert result.status == "unavailable"
    assert "RuntimeError" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.parametrize(
    "text",
    ["Plain text", "ＷＩＮ cash", "pa​y n‍ow", "café", "½ off"],
)
def test_features_match_the_training_input_form(text: str) -> None:
    # ml/scamshield_ml/prepare.py model_input: NFC, NFKC, then drop category Cf.
    folded = unicodedata.normalize("NFKC", unicodedata.normalize("NFC", text))
    expected = "".join(ch for ch in folded if unicodedata.category(ch) != "Cf")
    assert normalize(text).features == expected
