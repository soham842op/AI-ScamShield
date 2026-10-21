"""The model artifact the backend loads.

A single joblib file holding a dict, so one SHA-256 covers the pipeline, the
thresholds and the version together. The backend verifies `MODEL_ARTIFACT_SHA256`
before it unpickles anything. Field names here are the backend's load contract.
"""

import hashlib
from pathlib import Path
from typing import Any

import joblib
import sklearn
from sklearn.pipeline import Pipeline

from scamshield_ml.thresholds import Thresholds

ARTIFACT_FORMAT = "scamshield-text-classifier"
FORMAT_VERSION = 1
ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"
CURRENT_PATH = ARTIFACTS_DIR / "current" / "model.joblib"


def bundle(
    pipeline: Pipeline,
    thresholds: Thresholds,
    *,
    model_version: str,
    data_sha256: dict[str, str],
    split_seed: str,
) -> dict[str, Any]:
    return {
        "format": ARTIFACT_FORMAT,
        "format_version": FORMAT_VERSION,
        "model_version": model_version,
        "sklearn_version": sklearn.__version__,
        "thresholds": {"suspicious": thresholds.suspicious, "high_risk": thresholds.high_risk},
        "data_sha256": dict(sorted(data_sha256.items())),
        "split_seed": split_seed,
        "pipeline": pipeline,
    }


def save(content: dict[str, Any], path: Path = CURRENT_PATH) -> str:
    """Write the artifact and return its SHA-256."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(content, path, compress=3)
    return hashlib.sha256(path.read_bytes()).hexdigest()
