import pytest

from app.api.route import _is_json_content_type


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("application/json", True),
        ("APPLICATION/JSON", True),
        ("application/json; charset=utf-8", True),
        ("application/json;charset=UTF-8", True),
        ('application/json; charset="utf-8"', True),
        ("application/json; charset=utf-16", False),
        ("application/json; charset=utf-8; extra=1", False),
        ("application/json; foo", False),
        ("application/jsonp", False),
        ("application/vnd.api+json", False),
        ("text/json", False),
        ("", False),
        (None, False),
    ],
)
def test_is_json_content_type(header: str | None, expected: bool) -> None:
    assert _is_json_content_type(header) is expected
