from __future__ import annotations

import re
from typing import Dict, Iterable, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_KEYS = re.compile(
    r"token|secret|password|passwd|authorization|api[-_]?key|session|cookie|jwt|credential",
    re.IGNORECASE,
)


def redact_url(url: str, show_sensitive: bool = False) -> str:
    if show_sensitive:
        return url
    try:
        parts = urlsplit(url)
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "[REDACTED]" if SENSITIVE_KEYS.search(key) else value))
        netloc = parts.netloc
        if "@" in netloc:
            netloc = "[REDACTED]@" + netloc.rsplit("@", 1)[1]
        return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))
    except ValueError:
        return url


def redact_headers(
    headers: Iterable[Tuple[str, str]], show_sensitive: bool = False
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for key, value in headers:
        if not show_sensitive and SENSITIVE_KEYS.search(key):
            result[key] = "[REDACTED]"
        else:
            result[key] = value
    return result


def safe_error(message: str) -> str:
    message = re.sub(r"(?i)(authorization|token|password)=([^\s&]+)", r"\1=[REDACTED]", message)
    return message[:500]

