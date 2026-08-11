from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: Optional[str] = None

    def display(self) -> str:
        if self.port is None:
            return self.host
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class Connection:
    process: str
    pid: int
    user: str
    fd: str
    family: str
    protocol: str
    local: Endpoint
    remote: Optional[Endpoint]
    state: str = ""
    path: str = "direct"

    def key(self) -> str:
        remote = self.remote.display() if self.remote else ""
        return f"{self.pid}|{self.fd}|{self.protocol}|{self.local.display()}|{remote}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Interface:
    name: str
    flags: List[str] = field(default_factory=list)
    mtu: Optional[int] = None
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    status: str = "unknown"

    @property
    def is_vpn(self) -> bool:
        prefixes = ("utun", "tun", "tap", "ppp", "ipsec", "wg")
        return self.name.lower().startswith(prefixes)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["is_vpn"] = self.is_vpn
        return result


@dataclass
class ProbeResult:
    target: str
    ok: bool
    duration_ms: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

