"""Secret redaction for strings and nested data."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

MASK = "[REDACTED]"

# Key names whose *values* are always masked when found in dicts / key=value text.
SENSITIVE_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "private_key",
    "privatekey",
    "private-key",
    "seed",
    "mnemonic",
    "cookie",
    "session",
    "credential",
)

_KEY_ALT = "|".join(re.escape(k) for k in SENSITIVE_KEYS)

# (pattern, replacement). Replacements keep the surrounding context readable.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # -----BEGIN ... PRIVATE KEY----- ... -----END ... PRIVATE KEY-----
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
        MASK,
    ),
    # Authorization: Bearer xxx / Basic xxx
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {MASK}"),
    # URL credentials: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), rf"\1{MASK}@"),
    # Query-string secrets: ?api_key=...&token=...
    (
        re.compile(rf"(?i)([?&](?:[\w-]*(?:{_KEY_ALT})[\w-]*)=)[^&\s\"']+"),
        rf"\1{MASK}",
    ),
    # key=value / key: value / "key": "value" with a sensitive key name
    (
        re.compile(
            rf"(?i)((?:[\w-]*(?:{_KEY_ALT})[\w-]*)[\"']?\s*[:=]\s*[\"']?)"
            rf"(?!\[REDACTED\]|(?:Bearer|Basic)\s)[^\s\"',;&}}\]]+"
        ),
        rf"\1{MASK}",
    ),
    # JSON Web Tokens
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), MASK),
    # AWS access key ids
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    # GitHub / Slack style tokens
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})\b"), MASK),
    # Telegram bot tokens: 123456789:AA...
    (re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), MASK),
    # 0x-prefixed 32-byte hex (EVM private keys)
    (re.compile(r"\b0x[0-9a-fA-F]{64}\b"), MASK),
    # Long base58 strings (e.g. 64-byte Solana secret keys are 87-88 chars)
    (re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{80,90}\b"), MASK),
)


class Redactor:
    """Mask secrets in text and data.

    Three layers, from most to least precise:

    1. **Registered secrets**: exact values you know about (load them from your config at
       startup). Matched wherever they appear, in any format.
    2. **Sensitive keys**: values of keys like ``password`` or ``api_key`` in dicts and in
       ``key=value`` text.
    3. **Patterns**: well-known token shapes (JWT, bearer headers, PEM keys, URL credentials...).

    The first line of defence is still to never log secrets; this is the safety net.
    """

    def __init__(
        self,
        secrets: Iterable[str] = (),
        *,
        min_secret_length: int = 8,
        extra_patterns: Iterable[tuple[str, str]] = (),
        extra_keys: Iterable[str] = (),
    ) -> None:
        self._min = min_secret_length
        self._secrets: list[str] = []
        self._patterns = list(_PATTERNS) + [(re.compile(p), r) for p, r in extra_patterns]
        self._keys = {k.lower() for k in (*SENSITIVE_KEYS, *extra_keys)}
        for s in secrets:
            self.register_secret(s)

    def register_secret(self, value: str | None) -> None:
        """Always mask this exact value. Very short values are ignored (too many false hits)."""
        if value and len(value) >= self._min and value not in self._secrets:
            # longest first so a secret containing another is masked whole
            self._secrets.append(value)
            self._secrets.sort(key=len, reverse=True)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, MASK)
        for pattern, replacement in self._patterns:
            text = pattern.sub(replacement, text)
        return text

    def is_sensitive_key(self, key: object) -> bool:
        k = str(key).lower()
        return any(s in k for s in self._keys)

    def redact_obj(self, obj: Any, _depth: int = 0) -> Any:
        """Return a redacted copy of nested dicts / lists / tuples / strings."""
        if _depth > 20:
            return MASK
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, Mapping):
            return {
                k: MASK if self.is_sensitive_key(k) and v is not None else self.redact_obj(v, _depth + 1)
                for k, v in obj.items()
            }
        if isinstance(obj, tuple):
            return tuple(self.redact_obj(v, _depth + 1) for v in obj)
        if isinstance(obj, (list, set, frozenset)):
            return [self.redact_obj(v, _depth + 1) for v in obj]
        return obj
