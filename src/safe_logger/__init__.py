"""safe-logger: logging that cannot leak secrets or be forged by untrusted input."""

from .handlers import JsonFormatter, RedactingFilter, setup_logging
from .redact import MASK, SENSITIVE_KEYS, Redactor
from .sanitize import sanitize

__all__ = [
    "MASK",
    "SENSITIVE_KEYS",
    "JsonFormatter",
    "RedactingFilter",
    "Redactor",
    "sanitize",
    "setup_logging",
]
__version__ = "0.1.0"
