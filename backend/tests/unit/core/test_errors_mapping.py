from app.core.errors import ApiError, validation_details, validation_error


def test_details_drop_input_ctx_and_url() -> None:
    errors = [
        {
            "type": "string_type",
            "loc": ("body", "text"),
            "msg": "bad",
            "input": "SECRET",
            "ctx": {"error": "SECRET"},
            "url": "https://errors.pydantic.dev/x",
        }
    ]
    assert validation_details(errors) == [{"field": "text", "issue": "invalid_type"}]


def test_limit_only_for_max_length() -> None:
    errors = [
        {"type": "max_length", "loc": ("body", "text"), "ctx": {"limit": 10000}},
        {"type": "invalid_unicode", "loc": ("body", "url"), "ctx": {"limit": 5}},
    ]
    assert validation_details(errors) == [
        {"field": "text", "issue": "max_length", "limit": 10000},
        {"field": "url", "issue": "invalid_unicode"},
    ]


def test_unknown_error_type_is_invalid_value() -> None:
    errors = [{"type": "uuid_parsing", "loc": ("body", "request_id")}]
    assert validation_details(errors)[0]["issue"] == "invalid_value"


def test_json_invalid_has_no_field() -> None:
    errors = [{"type": "json_invalid", "loc": ("body", 17)}]
    assert validation_details(errors) == [{"field": None, "issue": "malformed_json"}]


def test_body_level_error_has_no_field() -> None:
    errors = [{"type": "model_attributes_type", "loc": ("body",)}]
    assert validation_details(errors) == [{"field": None, "issue": "invalid_type"}]


def test_unknown_field_name_is_never_echoed() -> None:
    for name in ("comment", "a b<script>", "x" * 65):
        errors = [{"type": "extra_forbidden", "loc": ("body", name)}]
        assert validation_details(errors) == [{"field": None, "issue": "unknown_field"}]


def test_code_is_input_too_long_only_when_all_issues_are_max_length() -> None:
    only_long = validation_error([{"field": "text", "issue": "max_length", "limit": 10000}])
    assert only_long.code == "input_too_long"
    assert only_long.status_code == 422
    mixed = validation_error(
        [{"field": "text", "issue": "max_length"}, {"field": "x", "issue": "unknown_field"}]
    )
    assert mixed.code == "validation_error"


def test_api_error_defaults() -> None:
    error = ApiError(429, headers={"Retry-After": "3"})
    assert error.code == "rate_limited"
    assert error.headers == {"Retry-After": "3"}
    assert ApiError(503).code == "service_unavailable"
    custom = ApiError(422, code="invalid_url", message="Nope.")
    assert (custom.code, custom.message) == ("invalid_url", "Nope.")
