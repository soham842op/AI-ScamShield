from scamshield_ml.load import RawExample
from scamshield_ml.prepare import (
    SPLITS,
    assign_split,
    dedup_key,
    group_key,
    model_input,
    prepare,
    split,
)


def _raw(text: str, label: str = "ham", dataset: str = "a") -> RawExample:
    return RawExample(dataset=dataset, source_label=label, text=text)  # type: ignore[arg-type]


def test_model_input_folds_compatibility_forms_and_drops_format_chars() -> None:
    # Fullwidth letters fold to ASCII; zero-width space and joiner are removed.
    assert model_input("ＷＩＮ​ ca‍sh") == "WIN cash"


def test_model_input_composes_to_nfc_first() -> None:
    assert model_input("café") == "café"


def test_dedup_key_ignores_case_and_whitespace() -> None:
    assert dedup_key("  Call   NOW\n") == dedup_key("call now")


def test_group_key_masks_digits_and_punctuation() -> None:
    assert group_key("Call 07700 900123 now!") == group_key("call 07700-900456, now")


def test_label_mapping() -> None:
    examples, _ = prepare(
        [_raw("a ham text", "ham"), _raw("a spam text", "spam"), _raw("a smish", "smishing")]
    )
    assert {e.source_label: e.target for e in examples} == {"ham": 0, "spam": 1, "smishing": 1}


def test_duplicates_across_datasets_merge_and_keep_the_specific_label() -> None:
    examples, stats = prepare(
        [_raw("Claim your prize", "spam", "a"), _raw("claim your  PRIZE", "smishing", "b")]
    )
    assert len(examples) == 1
    assert examples[0].source_label == "smishing"
    assert examples[0].datasets == frozenset({"a", "b"})
    assert stats.duplicates_merged == 1
    assert stats.in_both_datasets == 1


def test_conflicting_targets_are_dropped() -> None:
    examples, stats = prepare([_raw("same text", "ham"), _raw("same text", "spam")])
    assert examples == []
    assert stats.conflicts_dropped == 1


def test_empty_texts_are_dropped() -> None:
    examples, stats = prepare([_raw("   "), _raw("​")])
    assert examples == []
    assert stats.empty_dropped == 2


def test_assign_split_is_deterministic_and_seeded() -> None:
    assert assign_split("some group") == assign_split("some group")
    groups = [f"group {i}" for i in range(200)]
    assert [assign_split(g, "one") for g in groups] != [assign_split(g, "two") for g in groups]


def test_split_fractions_are_roughly_70_15_15() -> None:
    counts = {name: 0 for name in SPLITS}
    for i in range(20_000):
        counts[assign_split(f"g{i}")] += 1
    assert 0.68 < counts["train"] / 20_000 < 0.72
    assert 0.13 < counts["validation"] / 20_000 < 0.17


def test_near_duplicates_never_cross_splits() -> None:
    raw = [_raw(f"Win {n} pounds call 0770090{n:04d}", "spam") for n in range(50)]
    raw += [_raw(f"message number {n} about lunch", "ham") for n in range(300)]
    examples, _ = prepare(raw)
    parts = split(examples)
    homes = {name for name, items in parts.items() for e in items if e.text.startswith("Win")}
    assert len(homes) == 1


def test_supplement_label_maps_to_scam_like() -> None:
    examples, _ = prepare([_raw("pay the fee now", "scam"), _raw("see you soon", "ham")])
    assert {e.source_label: e.target for e in examples} == {"scam": 1, "ham": 0}
