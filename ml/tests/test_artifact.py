import hashlib
from pathlib import Path

import joblib

from scamshield_ml import artifact
from scamshield_ml.model import CANDIDATES, build
from scamshield_ml.thresholds import Thresholds

_TEXTS = ["win a prize now", "claim your reward", "see you at lunch", "meeting moved to 3"] * 3
_TARGETS = [1, 1, 0, 0] * 3


def _content() -> dict[str, object]:
    pipeline = build(CANDIDATES[-1]).fit(_TEXTS, _TARGETS)
    return artifact.bundle(
        pipeline,
        Thresholds(suspicious=0.3, high_risk=0.7),
        model_version="tfidf-logreg-test",
        data_sha256={"b": "2" * 64, "a": "1" * 64},
        split_seed="seed",
    )


def test_save_returns_file_sha256_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    digest = artifact.save(_content(), path)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    loaded = joblib.load(path)
    assert loaded["format"] == artifact.ARTIFACT_FORMAT
    assert loaded["format_version"] == artifact.FORMAT_VERSION
    assert loaded["thresholds"] == {"suspicious": 0.3, "high_risk": 0.7}
    assert list(loaded["data_sha256"]) == ["a", "b"]
    score = loaded["pipeline"].predict_proba(["claim your prize"])[0, 1]
    assert 0.0 <= score <= 1.0


def test_same_training_gives_same_bytes(tmp_path: Path) -> None:
    first = artifact.save(_content(), tmp_path / "one.joblib")
    second = artifact.save(_content(), tmp_path / "two.joblib")
    assert first == second
