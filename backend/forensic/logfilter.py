"""Keeps evidence out of the server log on an instance open to strangers.

Parsers log failures, and an exception's message is often a piece of the input: a
UnicodeDecodeError quotes the bytes, a ValueError the value, a KeyError the key. In browser-only
mode the log is the one thing that outlives a parse, so a record from the parsing code keeps its
message template and the exception's type and location, and loses the exception's text."""

from __future__ import annotations

import logging
import traceback

# loggers whose records may carry evidence: the parsers and analysers, and the views that call them
_EVIDENCE_LOGGERS = ("services.", "api.")


def _describe(exc: BaseException) -> str:
    tb = traceback.extract_tb(exc.__traceback__)[-1:] if exc.__traceback__ else []
    where = f" at {tb[0].filename.rsplit('/', 1)[-1]}:{tb[0].lineno}" if tb else ""
    return f"{type(exc).__name__}{where}"


class RedactEvidence(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not record.name.startswith(_EVIDENCE_LOGGERS):
            return True
        if record.args:
            args = record.args if isinstance(record.args, tuple) else (record.args,)
            record.args = tuple(_describe(a) if isinstance(a, BaseException) else a for a in args)
        if record.exc_info and record.exc_info[1] is not None:
            record.msg = f"{record.getMessage()} [{_describe(record.exc_info[1])}]"
            record.args = None
            record.exc_info = None
            record.exc_text = None
        return True
