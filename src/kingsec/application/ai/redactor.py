from __future__ import annotations

import re
from typing import ClassVar


class Redactor:
    """Redacts sensitive data before sending to AI providers.

    Never sends:
    - API keys, tokens, passwords
    - License keys
    - JWTs
    - Internal paths
    - Credentials
    """

    _PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+", re.MULTILINE),
        re.compile(r"\bsk-[A-Za-z0-9]{12,}\b"),
        re.compile(r"(?i)\b(?:license[_-]?key|licence[_-]?key)\s*[=:]\s*\S+", re.MULTILINE),
        re.compile(r"(?i)\bjwt\s*[=:]\s*[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", re.MULTILINE),
        re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret|credential)\s*[=:]\s*\S+", re.MULTILINE),
        re.compile(r"\b[A-Z][A-Z0-9_]{3,}=\S+"),
        re.compile(r"(?:^|\s)(/(?:etc|home|root|var|usr|opt)/[^\s]*)"),
        re.compile(r"[A-Za-z]:\\[^\s]+"),
        re.compile(r"(?im)^\s*File\s+\".*\",\s+line\s+\d+"),
        re.compile(r"(?i)\btraceback\s+\(most\s+recent\s+call\s+last\)"),
    ]

    _REDACTED = "[redacted]"

    def redact(self, text: str) -> str:
        if not text:
            return text
        result = text
        for pattern in self._PATTERNS:
            result = pattern.sub(self._REDACTED, result)
        return result

    def redact_messages(self, messages: list[dict[str, str]]) -> list[dict[str, str]]:
        return [{k: self.redact(v) if isinstance(v, str) else v for k, v in m.items()} for m in messages]
