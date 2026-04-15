"""Log sanitization — strip sensitive data before it reaches loguru sinks."""

from __future__ import annotations

import re
from typing import Any

# Each entry is (compiled_pattern, replacement_template).
_RAW_PATTERNS: list[tuple[str, str]] = [
    # API keys, tokens, secrets, passwords (key=value or key: value)
    (
        r'(api[_-]?key|apikey|token|secret|password|credential)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{8,})["\']?',
        r'\1=***REDACTED***',
    ),
    # Email addresses
    (
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        r'***@***.***',
    ),
    # Chinese mobile (11-digit starting 1[3-9]) and common international format
    (
        r'\b(\+?86[-\s]?)?1[3-9]\d{9}\b',
        r'***-****-****',
    ),
    # North American 10-digit (NXX-NXX-XXXX with optional separators)
    (
        r'\b\d{3}[.\-]\d{3}[.\-]\d{4}\b',
        r'***-****-****',
    ),
    # IPv4 addresses (coarse — avoids matching version strings like 1.2.3)
    (
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        r'*.*.*.*',
    ),
    # Bank card numbers / ID card numbers (15-19 consecutive digits)
    (
        r'\b\d{15,19}\b',
        r'****-****-****-****',
    ),
    # Telegram Bot Token  (123456789:AABBccdd...)
    (
        r'\b\d{8,10}:[A-Za-z0-9_\-]{35}\b',
        r'***TELEGRAM_TOKEN***',
    ),
]

_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, re.IGNORECASE), replacement)
    for pattern, replacement in _RAW_PATTERNS
]


class LogSanitizer:
    """Redact sensitive data from log messages.

    Usage with loguru::

        from loguru import logger
        from nanobot.security.logging import LogSanitizer

        logger.remove()
        logger.add(sys.stderr, filter=LogSanitizer.loguru_filter)
    """

    @classmethod
    def sanitize(cls, message: str) -> str:
        """Apply all redaction patterns to *message* and return the sanitized string."""
        if not message or not isinstance(message, str):
            return message
        result = message
        for pattern, replacement in _COMPILED:
            result = pattern.sub(replacement, result)
        return result

    @classmethod
    def loguru_filter(cls, record: dict[str, Any]) -> bool:
        """Loguru filter: sanitize ``record["message"]`` in place.

        Always returns ``True`` so the record is never dropped — only sanitized.
        """
        record["message"] = cls.sanitize(record["message"])
        return True
