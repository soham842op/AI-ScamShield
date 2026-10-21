import json
import re

from scamshield_ml import supplement, synthetic
from scamshield_ml.prepare import TARGETS, dedup_key, group_key, prepare

_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_PHONE = re.compile(r"\b0\d{3,4}\s?\d{6}\b")
_ALLOWED_PHONE = re.compile(r"\b(?:07700\s?900\d{3}|01632\s?960\d{3})\b")
# Brands invented for the synthetic evaluation set; the supplement must not reuse them.
_EVAL_BRANDS = (
    "parcelpost",
    "swiftship",
    "northbank",
    "harbor credit",
    "streamflix",
    "shopmart",
    "brightenergy",
    "netlink",
    "greenleaf",
    "olive grove",
    "skyair",
    "brightpath",
    "ezroad",
)


def test_set_loads_and_is_balanced() -> None:
    rows = supplement.read()
    assert len(rows) == 600
    assert sum(TARGETS[r.source_label] for r in rows) == 300
    assert {r.dataset for r in rows} == {supplement.DATASET}


def test_manifest_matches_set() -> None:
    manifest = json.loads(supplement.MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["set"] == supplement.SET_PATH.name
    assert manifest["examples"] == len(supplement.read())


def test_only_reserved_domains_and_numbers() -> None:
    for row in supplement.read():
        for domain in _DOMAIN.findall(row.text):
            assert domain.lower().endswith(".example"), domain
        for phone in _PHONE.findall(row.text):
            assert _ALLOWED_PHONE.fullmatch(phone), phone


def test_no_brand_or_message_shared_with_the_evaluation_set() -> None:
    rows = supplement.read()
    for row in rows:
        lowered = row.text.lower()
        assert not any(brand in lowered for brand in _EVAL_BRANDS), row.text[:30]
    evaluation = synthetic.load()
    assert not {dedup_key(r.text) for r in rows} & {dedup_key(e.text) for e in evaluation}
    assert not {group_key(r.text) for r in rows} & {group_key(e.text) for e in evaluation}


def test_supplement_scam_label_is_scam_like() -> None:
    examples, _ = prepare(supplement.read())
    assert {e.source_label: e.target for e in examples} == {"scam": 1, "ham": 0}
