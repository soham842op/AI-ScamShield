from app.pipeline.normalize import normalize


def test_display_is_nfc_and_features_are_nfkc() -> None:
    result = normalize("Café ＡＢＣ")
    assert result.display == "Café ＡＢＣ"
    assert result.features == "Café ABC"


def test_zero_width_and_bidi_removed_from_features_only() -> None:
    result = normalize("pass\u200bword \u202eabc")
    assert "\u200b" in result.display
    assert result.features == "password abc"
    assert result.obfuscated is True


def test_plain_text_is_not_obfuscated() -> None:
    assert normalize("Your parcel arrives tomorrow.").obfuscated is False


def test_mixed_latin_cyrillic_word_is_obfuscated() -> None:
    assert normalize("verify your pаypal account").obfuscated is True


def test_mixed_latin_greek_word_is_obfuscated() -> None:
    assert normalize("gοogle login").obfuscated is True


def test_separate_scripts_in_separate_words_are_fine() -> None:
    assert normalize("hello привет αβγ").obfuscated is False


def test_short_unit_symbol_is_not_flagged() -> None:
    assert normalize("5 μm").obfuscated is False


def test_joiner_inside_emoji_sequence_is_not_flagged() -> None:
    family = "\U0001f469\u200d\U0001f469\u200d\U0001f467"
    result = normalize(f"hi {family}")
    assert result.obfuscated is False
    assert "\u200d" not in result.features


def test_empty_text() -> None:
    result = normalize("")
    assert (result.display, result.features, result.obfuscated) == ("", "", False)


def test_soft_hyphen_alone_is_not_obfuscation() -> None:
    result = normalize("co\u00adoperate")
    assert result.obfuscated is False
    assert result.features == "cooperate"


def test_soft_hyphen_does_not_hide_other_format_chars() -> None:
    assert normalize("co\u00ado\u200bperate").obfuscated is True
