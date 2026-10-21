"""Text normalization for the rules engine.

`display` keeps what the user wrote (NFC) and is the text URLs are extracted from.
`features` is what the rules match against: compatibility-folded and with
invisible format characters removed, so zero-width padding cannot split a phrase.
"""

import re
import unicodedata
from dataclasses import dataclass

_LETTER_RUN = re.compile(r"[^\W\d_]+")
_MIXABLE_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")
# Common in ordinary hyphenated text, so it alone is not a sign of disguise.
_SOFT_HYPHEN = "\u00ad"
_ZWJ = "\u200d"
# A word shorter than this is too short to tell a disguise from a unit symbol.
_MIN_MIXED_WORD = 3


@dataclass(frozen=True, slots=True)
class NormalizedText:
    display: str
    features: str
    obfuscated: bool


def _is_format_char(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf"


def _script(ch: str) -> str | None:
    name = unicodedata.name(ch, "")
    for script in _MIXABLE_SCRIPTS:
        if name.startswith(script + " "):
            return script
    return None


def _has_hidden_format_chars(text: str) -> bool:
    for index, ch in enumerate(text):
        if not _is_format_char(ch) or ch == _SOFT_HYPHEN:
            continue
        # A joiner inside an emoji sequence is ordinary text, not a disguise.
        if ch == _ZWJ and index > 0 and unicodedata.category(text[index - 1]) in ("So", "Sk"):
            continue
        return True
    return False


def _has_mixed_script_word(text: str) -> bool:
    for match in _LETTER_RUN.finditer(text):
        word = match.group()
        if len(word) < _MIN_MIXED_WORD:
            continue
        scripts = {s for s in map(_script, word) if s is not None}
        if "LATIN" in scripts and len(scripts) > 1:
            return True
    return False


def normalize(text: str) -> NormalizedText:
    display = unicodedata.normalize("NFC", text)
    folded = unicodedata.normalize("NFKC", display)
    features = "".join(ch for ch in folded if not _is_format_char(ch))
    obfuscated = _has_hidden_format_chars(display) or _has_mixed_script_word(display)
    return NormalizedText(display=display, features=features, obfuscated=obfuscated)
