from __future__ import annotations

import math
import ipaddress
import re
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"

SENSITIVE_KEYS = re.compile(
    r"token|secret|password|passwd|authorization|api[-_]?key|session|cookie|jwt|credential",
    re.IGNORECASE,
)

_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----",
    re.DOTALL,
)
_AUTHORIZATION_VALUE = re.compile(
    r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{4,})"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?![A-Za-z0-9_-])"
)
_KNOWN_SECRET_PATTERNS = (
    ("GitHub token", re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])")),
    ("AWS access key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("Stripe key", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9_])")),
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:token|authorization|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|password|passwd|api[_-]?key)\b\s*[:=]\s*)([^\s,;&]+)"
)
_ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}(?![A-Za-z0-9+/_=-])")
_URL_IN_TEXT = re.compile(r"(?i)\b(?:https?|wss?)://[^\s<>\"']+")
_IPV4_CANDIDATE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[A-Za-z0-9_.-]+)?(?![0-9A-Fa-f:])")
_EMAIL_ADDRESS = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
_MAC_ADDRESS = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_LOCAL_PATH = re.compile(
    r"(?:(?<![\w:/])/(?!/)[^\s\"'`,;<>]+|(?<!\w)~/[^\s\"'`,;<>]+|"
    r"(?i:(?<![A-Z0-9_])[A-Z]:\\[^\s\"'`,;<>]+|(?<!\\)\\\\[^\s\"'`,;<>]+))"
)


@dataclass(frozen=True)
class RedactionRules:
    """Additive privacy rules used by recorders and share-safe exporters.

    Patterns are case-insensitive shell globs. ``path_patterns`` match dotted
    object paths (for example ``source_metadata.path``) and URL paths.  Custom
    rules augment, rather than replace, WireScope's built-in secret rules.
    """

    key_patterns: Tuple[str, ...] = ()
    header_patterns: Tuple[str, ...] = ()
    path_patterns: Tuple[str, ...] = ()
    redact_all_query_values: bool = False
    redact_all_headers: bool = False
    redact_url_paths: bool = False
    remove_url_fragments: bool = False
    detect_value_secrets: bool = True
    detect_high_entropy: bool = True
    redact_ip_addresses: bool = False
    redact_email_addresses: bool = False
    redact_hardware_addresses: bool = False
    redact_local_paths: bool = False
    high_entropy_min_length: int = 32
    high_entropy_max_length: int = 256
    high_entropy_threshold: float = 4.2
    max_value_chars: int = 1_000_000

    def __post_init__(self) -> None:
        for field_name in ("key_patterns", "header_patterns", "path_patterns"):
            raw_values = getattr(self, field_name)
            if isinstance(raw_values, str):
                raw_values = (raw_values,)
            values = tuple(str(value) for value in raw_values if str(value))
            object.__setattr__(self, field_name, values)
        if self.high_entropy_min_length < 1:
            raise ValueError("high_entropy_min_length must be positive")
        if self.high_entropy_max_length < self.high_entropy_min_length:
            raise ValueError("high_entropy_max_length cannot be smaller than high_entropy_min_length")
        if self.high_entropy_threshold < 0:
            raise ValueError("high_entropy_threshold cannot be negative")
        if self.max_value_chars < 1:
            raise ValueError("max_value_chars must be positive")

    def extend(
        self,
        *,
        keys: Iterable[str] = (),
        headers: Iterable[str] = (),
        paths: Iterable[str] = (),
        **overrides: Any,
    ) -> "RedactionRules":
        """Return a policy with additional user rules and optional flag overrides."""

        additions: Dict[str, Any] = {
            "key_patterns": self.key_patterns + tuple(str(value) for value in keys),
            "header_patterns": self.header_patterns + tuple(str(value) for value in headers),
            "path_patterns": self.path_patterns + tuple(str(value) for value in paths),
        }
        additions.update(overrides)
        return replace(self, **additions)


DEFAULT_REDACTION_RULES = RedactionRules()
SHARE_SAFE_REDACTION_RULES = RedactionRules(
    key_patterns=(
        "remote_ip",
        "remoteIPAddress",
        "local_ip",
        "client_ip",
        "server_ip",
        "ip_address",
        "postData",
        "postDataEntries",
        "body",
        "payloadData",
        "headersText",
        "requestHeadersText",
        "responseHeadersText",
        "node",
        "hostname",
        "host_name",
        "computer_name",
        "device_name",
        "username",
        "user",
        "account",
        "account_id",
        "user_id",
        "device_id",
        "machine_id",
        "installation_id",
        "client_id",
        "serial",
        "serial_number",
        "ssid",
        "bssid",
        "source_path",
    ),
    header_patterns=("*",),
    path_patterns=(
        "source_metadata.path",
        "*.source_metadata.path",
        "requests.*.path",
        "*.requests.*.path",
        "summary.path",
        "*.config.source",
        "*.source_path",
    ),
    redact_all_query_values=True,
    redact_all_headers=True,
    redact_url_paths=True,
    remove_url_fragments=True,
    redact_ip_addresses=True,
    redact_email_addresses=True,
    redact_hardware_addresses=True,
    redact_local_paths=True,
)


def strict_share_safe_rules(additional: Optional[RedactionRules] = None) -> RedactionRules:
    """Return the mandatory share-safe baseline plus additive user patterns."""

    if additional is None or additional is SHARE_SAFE_REDACTION_RULES:
        return SHARE_SAFE_REDACTION_RULES
    already_strict = (
        additional.redact_all_query_values
        and additional.redact_all_headers
        and additional.redact_url_paths
        and additional.remove_url_fragments
        and additional.detect_value_secrets
        and additional.detect_high_entropy
        and additional.redact_ip_addresses
        and additional.redact_email_addresses
        and additional.redact_hardware_addresses
        and additional.redact_local_paths
        and set(SHARE_SAFE_REDACTION_RULES.key_patterns).issubset(additional.key_patterns)
        and set(SHARE_SAFE_REDACTION_RULES.header_patterns).issubset(additional.header_patterns)
        and set(SHARE_SAFE_REDACTION_RULES.path_patterns).issubset(additional.path_patterns)
    )
    if already_strict:
        return additional
    return SHARE_SAFE_REDACTION_RULES.extend(
        keys=additional.key_patterns,
        headers=additional.header_patterns,
        paths=additional.path_patterns,
    )


def _rules(value: Optional[RedactionRules]) -> RedactionRules:
    return value or DEFAULT_REDACTION_RULES


def _glob_matches(value: str, patterns: Sequence[str]) -> bool:
    lowered = value.casefold()
    return any(fnmatchcase(lowered, pattern.casefold()) for pattern in patterns)


def is_sensitive_key(
    key: str,
    rules: Optional[RedactionRules] = None,
    *,
    header: bool = False,
) -> bool:
    policy = _rules(rules)
    if SENSITIVE_KEYS.search(str(key)):
        return True
    patterns = policy.header_patterns if header else policy.key_patterns
    return _glob_matches(str(key), patterns)


def is_sensitive_path(path: Union[Sequence[str], str], rules: Optional[RedactionRules] = None) -> bool:
    policy = _rules(rules)
    dotted = path if isinstance(path, str) else ".".join(str(value) for value in path)
    return bool(dotted and _glob_matches(dotted, policy.path_patterns))


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_high_entropy(value: str, rules: RedactionRules) -> bool:
    if not rules.detect_high_entropy:
        return False
    if len(value) < rules.high_entropy_min_length:
        return False
    sample = value[: rules.high_entropy_max_length]
    categories = sum(
        bool(re.search(pattern, sample))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/_=-]")
    )
    # Requiring three character classes avoids treating ordinary long words,
    # UUIDs, and most file names as credentials.
    return categories >= 3 and _entropy(sample) >= rules.high_entropy_threshold


def contains_secret(value: str, rules: Optional[RedactionRules] = None) -> bool:
    """Return whether a bounded scalar resembles a credential or private key."""

    policy = _rules(rules)
    if not policy.detect_value_secrets or not value:
        return False
    candidate = value[: policy.max_value_chars]
    if _PEM_PRIVATE_KEY.search(candidate) or _AUTHORIZATION_VALUE.search(candidate) or _JWT.search(candidate):
        return True
    if _SENSITIVE_ASSIGNMENT.search(candidate):
        return True
    if any(pattern.search(candidate) for _label, pattern in _KNOWN_SECRET_PATTERNS):
        return True
    return any(_looks_high_entropy(match.group(0), policy) for match in _ENTROPY_CANDIDATE.finditer(candidate))


def redact_text(value: str, rules: Optional[RedactionRules] = None) -> str:
    """Redact known credentials embedded in an otherwise ordinary string.

    Inspection is deliberately bounded. Oversized scalar values are truncated
    instead of leaving an uninspected tail in a supposedly sanitized artifact.
    """

    policy = _rules(rules)
    if not policy.detect_value_secrets or not value:
        return value
    truncated = len(value) > policy.max_value_chars
    result = value[: policy.max_value_chars]
    if policy.redact_all_query_values or policy.redact_url_paths or policy.remove_url_fragments:
        result = _URL_IN_TEXT.sub(lambda match: redact_url(match.group(0), rules=policy), result)
    result = _PEM_PRIVATE_KEY.sub("[REDACTED PEM PRIVATE KEY]", result)
    result = _AUTHORIZATION_VALUE.sub(lambda match: f"{match.group(1)} {REDACTED}", result)
    result = _JWT.sub("[REDACTED JWT]", result)
    for label, pattern in _KNOWN_SECRET_PATTERNS:
        result = pattern.sub(f"[REDACTED {label.upper()}]", result)
    result = _SENSITIVE_ASSIGNMENT.sub(lambda match: match.group(1) + REDACTED, result)
    if policy.redact_ip_addresses:
        result = _IPV4_CANDIDATE.sub(
            lambda match: "[REDACTED IP]"
            if _valid_ip(match.group(0))
            else match.group(0),
            result,
        )
        result = _IPV6_CANDIDATE.sub(
            lambda match: "[REDACTED IP]"
            if _valid_ip(match.group(0))
            else match.group(0),
            result,
        )
    if policy.redact_email_addresses:
        result = _EMAIL_ADDRESS.sub("[REDACTED EMAIL]", result)
    if policy.redact_hardware_addresses:
        result = _MAC_ADDRESS.sub("[REDACTED MAC]", result)
    if policy.redact_local_paths:
        result = _LOCAL_PATH.sub("[REDACTED LOCAL PATH]", result)
    result = _ENTROPY_CANDIDATE.sub(
        lambda match: "[REDACTED HIGH-ENTROPY VALUE]" if _looks_high_entropy(match.group(0), policy) else match.group(0),
        result,
    )
    if truncated:
        result += "[TRUNCATED FOR PRIVACY]"
    return result


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return True


def redact_url(
    url: str,
    show_sensitive: bool = False,
    rules: Optional[RedactionRules] = None,
) -> str:
    if show_sensitive:
        return url
    policy = _rules(rules)
    try:
        parts = urlsplit(url)
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            redacted_value = redact_text(value, policy)
            if policy.redact_all_query_values or is_sensitive_key(key, policy) or redacted_value != value:
                redacted_value = REDACTED
            query.append((key, redacted_value))
        netloc = parts.netloc
        userinfo = ""
        if "@" in netloc:
            userinfo = REDACTED + "@"
            netloc = netloc.rsplit("@", 1)[1]
        hostname = parts.hostname
        if policy.redact_ip_addresses and hostname and _valid_ip(hostname):
            port = parts.port
            netloc = "[REDACTED-IP]" + (f":{port}" if port is not None else "")
        netloc = userinfo + netloc
        path = parts.path
        if path and path != "/" and (policy.redact_url_paths or is_sensitive_path(path, policy)):
            path = "/[REDACTED PATH]"
        else:
            path = redact_text(path, policy)
        fragment = "" if policy.remove_url_fragments else redact_text(parts.fragment, policy)
        return urlunsplit((parts.scheme, netloc, path, urlencode(query), fragment))
    except (TypeError, ValueError):
        return redact_text(str(url), policy)


def redact_headers(
    headers: Union[Iterable[Tuple[str, str]], Mapping[str, Any]],
    show_sensitive: bool = False,
    rules: Optional[RedactionRules] = None,
) -> Dict[str, str]:
    policy = _rules(rules)
    values = headers.items() if isinstance(headers, Mapping) else headers
    result: Dict[str, str] = {}
    for key, value in values:
        name = str(key)
        text = str(value)
        if not show_sensitive and (policy.redact_all_headers or is_sensitive_key(name, policy, header=True)):
            result[name] = REDACTED
        else:
            result[name] = text if show_sensitive else redact_text(text, policy)
    return result


def redact_structure(
    value: Any,
    rules: Optional[RedactionRules] = None,
    *,
    path: Tuple[str, ...] = (),
) -> Any:
    """Recursively sanitize JSON-compatible data using key/header/path rules."""

    policy = _rules(rules)
    if is_sensitive_path(path, policy):
        return REDACTED
    if isinstance(value, Mapping):
        result: Dict[Any, Any] = {}
        header_container = any("header" in component.casefold() for component in path)
        header_record = header_container and "name" in value and "value" in value
        header_name = str(value.get("name", "")) if header_record else ""
        for key, item in value.items():
            key_text = str(key)
            output_key: Any = redact_text(key_text, policy) if isinstance(key, str) else key
            if output_key in result:
                base = str(output_key)
                suffix = 2
                while f"{base}#{suffix}" in result:
                    suffix += 1
                output_key = f"{base}#{suffix}"
            child_path = path + (key_text,)
            if header_record and key_text.casefold() == "name":
                result[output_key] = redact_text(str(item), policy)
            elif header_record and key_text.casefold() == "value" and (
                policy.redact_all_headers or is_sensitive_key(header_name, policy, header=True)
            ):
                result[output_key] = REDACTED
            elif is_sensitive_path(child_path, policy) or is_sensitive_key(
                key_text, policy, header=header_container
            ):
                result[output_key] = REDACTED
            elif key_text.casefold().endswith("url") and isinstance(item, str):
                result[output_key] = redact_url(item, rules=policy)
            else:
                result[output_key] = redact_structure(item, policy, path=child_path)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_structure(item, policy, path=path + (str(index),)) for index, item in enumerate(value)]
    if isinstance(value, str):
        return redact_text(value, policy)
    return value


def safe_error(message: str, rules: Optional[RedactionRules] = None) -> str:
    return redact_text(str(message), rules)[:500]
