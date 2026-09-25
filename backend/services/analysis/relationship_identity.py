"""Conservative identities shared by the graph and collection resolver."""

import uuid

from services.parsers.collection import timestamp


def instant(value):
    """Normalized event milliseconds or an explicitly zoned collector timestamp."""
    return value if type(value) is int else timestamp(value)


def numeric_id(value):
    try:
        text = str(value).strip()
        number = int(text, 16 if text.lower().startswith("0x") else 10)
        return str(number) if 0 < number <= 0xFFFFFFFFFFFFFFFF else ""
    except (ValueError, TypeError):
        return ""


def process_guid(value):
    try:
        parsed = uuid.UUID(str(value).strip().strip("{}"))
        return str(parsed) if parsed.int else ""
    except (ValueError, TypeError, AttributeError):
        return ""
