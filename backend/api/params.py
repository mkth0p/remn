"""Numeric request parameters. A value that is not a number is the client's mistake, so it is
answered with a 400 that names the parameter rather than with the 500 an uncaught int() gives."""

from __future__ import annotations

import math
from typing import Any


class BadParameter(ValueError):
    """A request parameter that cannot be read. Its text is written for the client."""


def whole_number(value: Any, name: str, default: int, minimum: int | None = None) -> int:
    """The parameter as an integer, or the default when it is absent, empty or zero."""
    said = f"{name} must be a whole number" + (f", {minimum} or more" if minimum is not None else "")
    if not value:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise BadParameter(said)
    try:
        number = int(value)
    except (ValueError, OverflowError):
        raise BadParameter(said) from None
    if minimum is not None and number < minimum:
        raise BadParameter(said)
    return number


def seconds(value: Any, name: str, default: float) -> float:
    """The parameter as a duration above zero, or the default when it is absent, empty or zero."""
    said = f"{name} must be a number of seconds above 0"
    if not value:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise BadParameter(said)
    try:
        number = float(value)
    except (ValueError, OverflowError):
        raise BadParameter(said) from None
    if not math.isfinite(number) or number <= 0:
        raise BadParameter(said)
    return number
