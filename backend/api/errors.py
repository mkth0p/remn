"""What a client is told when the server fails.

An exception's text is often a piece of the input or a path on this machine: a decode error
quotes the bytes, an OSError names the file, a database error the statement. None of that belongs
in a response. The client is told what failed, the exception's type and a reference; the log line
that records the exception carries the same reference, so the operator can find the cause for the
analyst who reports it. Messages the code composes for the analyst are returned where they are
raised and do not come through here."""

from __future__ import annotations

import logging
import secrets


def failure(what: str, exc: BaseException, logger: logging.Logger) -> dict[str, str]:
    """The error fields of a response for a failure of `what`, logged under a new reference."""
    ref = secrets.token_hex(4)
    # the exception goes to the log as exc_info, never as text in the message: the log filter
    # reduces exc_info to type and place, and cannot do that for text
    logger.error("%s failed [ref %s]", what, ref, exc_info=exc)
    return {"error": f"{what} failed on the server ({type(exc).__name__}); the server log has the cause under reference {ref}", "ref": ref}
