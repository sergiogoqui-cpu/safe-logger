"""Integration with the standard :mod:`logging` module."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redact import Redactor
from .sanitize import sanitize

# Attributes every LogRecord has; anything else came from ``extra=``.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime", "taskName"}


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    return {k: v for k, v in vars(record).items() if k not in _STANDARD and not k.startswith("_")}


class RedactingFilter(logging.Filter):
    """Redact a record in place: message, args, ``extra=`` fields and exception text.

    Attach to a handler (or logger) when you want to keep your own formatter.
    """

    def __init__(self, redactor: Redactor | None = None, *, max_length: int | None = 2000) -> None:
        super().__init__()
        self.redactor = redactor or Redactor()
        self.max_length = max_length

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = sanitize(self.redactor.redact(message), max_length=self.max_length)
        record.args = None
        for key, value in _extras(record).items():
            if self.redactor.is_sensitive_key(key):
                setattr(record, key, "[REDACTED]")
            elif isinstance(value, (str, dict, list, tuple)):
                safe = self.redactor.redact_obj(value)
                setattr(record, key, sanitize(safe, max_length=self.max_length) if isinstance(safe, str) else safe)
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = self.redactor.redact(record.exc_text)
        if record.stack_info:
            record.stack_info = self.redactor.redact(record.stack_info)
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: easy to grep, ship and parse."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "at": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            **_extras(record),
        }
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            entry["exc"] = record.exc_text
        return json.dumps(entry, default=str, ensure_ascii=False)


def setup_logging(
    level: int | str = "INFO",
    *,
    secrets: list[str] | None = None,
    redactor: Redactor | None = None,
    json_output: bool = False,
    file: str | Path | None = None,
    max_length: int | None = 2000,
) -> Redactor:
    """Configure the root logger with redaction on every handler. Returns the ``Redactor``.

    >>> redactor = setup_logging("INFO", secrets=[os.environ["API_SECRET"]])
    """
    redactor = redactor or Redactor(secrets or ())
    formatter: logging.Formatter = (
        JsonFormatter()
        if json_output
        else logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if file is not None:
        path = Path(file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(path, encoding="utf-8"))

    root = logging.getLogger()
    root.setLevel(level)
    for old in list(root.handlers):
        root.removeHandler(old)
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(RedactingFilter(redactor, max_length=max_length))
        root.addHandler(handler)
    return redactor
