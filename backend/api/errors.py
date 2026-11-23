"""What a client is told when the server fails.

An exception's text is often a piece of the input or a path on this machine: a decode error
quotes the bytes, an OSError names the file, a database error the statement. None of that belongs
in a response. The client is told what failed, the exception's type and a reference; the log line
that records the exception carries the same reference, so the operator can find the cause for the
analyst who reports it. Text the code wrote for the analyst is raised as an AnalystMessage and is
told as it is, wherever it is caught."""

from __future__ import annotations

import logging
import secrets

from services.common import AnalystMessage


def failure(what: str, exc: BaseException, logger: logging.Logger) -> dict[str, str]:
    """The error fields of a response for a failure of `what`, logged under a new reference; or,
    for an AnalystMessage, its own text."""
    if isinstance(exc, AnalystMessage):
        return {"error": str(exc)}
    ref = secrets.token_hex(4)
    # the exception goes to the log as exc_info, never as text in the message: the log filter
    # reduces exc_info to type and place, and cannot do that for text
    logger.error("%s failed [ref %s]", what, ref, exc_info=exc)
    return {"error": f"{what} failed on the server ({type(exc).__name__}); the server log has the cause under reference {ref}", "ref": ref}
