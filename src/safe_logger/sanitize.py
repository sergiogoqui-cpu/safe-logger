"""Neutralise untrusted text before it reaches a log."""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def sanitize(text: str, *, max_length: int | None = 2000) -> str:
    """Make untrusted text safe to log.

    - Strips ANSI escape sequences (terminal tricks).
    - Escapes newlines, so an attacker can't forge extra log lines (log injection).
    - Replaces other control characters with ``?``.
    - Truncates very long values.
    """
    text = _ANSI.sub("", text)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    text = _CONTROL.sub("?", text)
    if max_length is not None and len(text) > max_length:
        extra = len(text) - max_length
        text = f"{text[:max_length]}...[+{extra} chars]"
    return text
