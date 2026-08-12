"""Offline Public Suffix List matching and registrable-domain helpers.

The matching algorithm follows the Public Suffix List specification, including
exact, wildcard and exception rules.  The bundled snapshot is loaded lazily and
never performs network I/O.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class DomainParts:
    host: str
    public_suffix: str
    registrable_domain: str
    matched_rule: str
    rule_type: str
    is_ip: bool = False


def canonical_host(host: str) -> str:
    """Return a stable lower-case ASCII hostname without a terminal dot."""

    value = (host or "").strip().rstrip(".").lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    labels = value.split(".")
    if any(not label for label in labels):
        return value
    try:
        return ".".join(label.encode("idna").decode("ascii") for label in labels)
    except UnicodeError:
        return value


class PublicSuffixList:
    """Compiled Public Suffix List with PSL-compatible prevailing-rule logic."""

    def __init__(self, rules: Iterable[str]) -> None:
        exact: Set[Tuple[str, ...]] = set()
        wildcard: Set[Tuple[str, ...]] = set()
        exception: Set[Tuple[str, ...]] = set()
        for raw_rule in rules:
            rule = raw_rule.split("//", 1)[0].strip().lower().rstrip(".")
            if not rule:
                continue
            target = exact
            if rule.startswith("!"):
                target = exception
                rule = rule[1:]
            elif rule.startswith("*."):
                target = wildcard
                rule = rule[2:]
            canonical = canonical_host(rule)
            if canonical:
                target.add(tuple(canonical.split(".")))
        self._exact = frozenset(exact)
        self._wildcard = frozenset(wildcard)
        self._exception = frozenset(exception)

    @classmethod
    def from_text(cls, text: str) -> "PublicSuffixList":
        return cls(text.splitlines())

    def _prevailing_rule(self, labels: Sequence[str]) -> Tuple[int, str, str]:
        matches = []
        # Hostnames have at most 127 labels, so probing their suffixes is both
        # simpler and dramatically cheaper than scanning every bundled rule.
        for start in range(len(labels)):
            candidate = tuple(labels[start:])
            if candidate in self._exception:
                return max(1, len(candidate) - 1), "!" + ".".join(candidate), "exception"
            if candidate in self._exact:
                matches.append((len(candidate), ".".join(candidate), "exact"))
            if start + 1 < len(labels):
                wildcard_base = tuple(labels[start + 1 :])
                if wildcard_base in self._wildcard:
                    matches.append((len(wildcard_base) + 1, "*." + ".".join(wildcard_base), "wildcard"))
        return max(matches, key=lambda item: item[0]) if matches else (1, "*", "default")

    @lru_cache(maxsize=8192)
    def split(self, host: str) -> DomainParts:
        normalized = canonical_host(host)
        if not normalized:
            return DomainParts("", "", "", "", "none")
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            pass
        else:
            return DomainParts(normalized, normalized, normalized, "ip-address", "ip", True)

        labels = normalized.split(".")
        if any(not label for label in labels):
            return DomainParts(normalized, normalized, normalized, "invalid-hostname", "invalid")
        suffix_count, rule, rule_type = self._prevailing_rule(labels)
        suffix_count = min(len(labels), suffix_count)
        public_suffix = ".".join(labels[-suffix_count:])
        # Preserve WireScope's historic behavior for a bare public suffix while
        # returning the real eTLD+1 whenever a registrable label exists.
        registrable = normalized if len(labels) <= suffix_count else ".".join(labels[-(suffix_count + 1) :])
        return DomainParts(normalized, public_suffix, registrable, rule, rule_type)

    def public_suffix(self, host: str) -> str:
        return self.split(host).public_suffix

    def registrable_domain(self, host: str) -> str:
        return self.split(host).registrable_domain


@lru_cache(maxsize=1)
def default_public_suffix_list() -> PublicSuffixList:
    from ._psl_snapshot import rules

    return PublicSuffixList(rules())


def registrable_domain(host: str, suffix_list: Optional[PublicSuffixList] = None) -> str:
    return (suffix_list or default_public_suffix_list()).registrable_domain(host)
