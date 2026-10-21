class InvalidUrlError(ValueError):
    """The submitted URL cannot be parsed or has no valid host."""


class UnsupportedSchemeError(ValueError):
    """The submitted URL has a scheme other than http or https."""
