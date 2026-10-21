import json
import re

from scamshield_ml.synthetic import MANIFEST_PATH, SET_PATH, load

_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_PHONE = re.compile(r"\b0\d{3,4}\s?\d{6}\b")
_ALLOWED_PHONE = re.compile(r"\b(?:07700\s?900\d{3}|01632\s?960\d{3})\b")


def test_set_loads_and_is_balanced() -> None:
    rows = load()
    assert len(rows) == 120
    assert sum(r.target for r in rows) == 60
    assert len({r.id for r in rows}) == len(rows)


def test_manifest_matches_set() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["set"] == SET_PATH.name
    assert manifest["examples"] == len(load())


def test_only_reserved_domains_and_numbers() -> None:
    for row in load():
        for domain in _DOMAIN.findall(row.text):
            assert domain.lower().endswith(".example"), row.id
        for phone in _PHONE.findall(row.text):
            assert _ALLOWED_PHONE.fullmatch(phone), row.id
