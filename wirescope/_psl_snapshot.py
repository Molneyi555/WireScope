"""Load the bundled Mozilla Public Suffix List source snapshot.

Upstream source: https://publicsuffix.org/list/public_suffix_list.dat
WireScope snapshot capture date: 2026-08-11
License for the snapshot: Mozilla Public License 2.0

``wirescope/data/public_suffix_list.dat`` is the preferred form for making
modifications and the exact offline data consumed at runtime.  WireScope
verifies its pinned SHA-256 digest and rule count before use; no network access
or third-party dependency is involved.  See ``THIRD_PARTY_NOTICES.md`` and
``LICENSES/MPL-2.0.txt`` in the distribution for provenance and license terms.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib import resources
from typing import Tuple

SNAPSHOT_DATE = "2026-08-11"
SNAPSHOT_RESOURCE = "public_suffix_list.dat"
RULE_COUNT = 8832
RULES_SHA256 = "d839a154060dfaf2f42a7b685bfa35e5119e5cf53f8ed34c6a7bcf6d418452a0"


def _snapshot_bytes() -> bytes:
    try:
        return resources.files("wirescope.data").joinpath(SNAPSHOT_RESOURCE).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise RuntimeError("bundled Public Suffix List source snapshot is missing") from exc


@lru_cache(maxsize=1)
def rules() -> Tuple[str, ...]:
    payload = _snapshot_bytes()
    if hashlib.sha256(payload).hexdigest() != RULES_SHA256:
        raise RuntimeError("bundled Public Suffix List snapshot failed integrity verification")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("bundled Public Suffix List snapshot is not valid UTF-8") from exc
    values = tuple(line for line in text.splitlines() if line)
    if len(values) != RULE_COUNT:
        raise RuntimeError("bundled Public Suffix List snapshot is corrupt")
    return values
