from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Generic, Iterable, List, Optional, Sequence, Tuple, TypeVar, Union

from .models import Connection, Endpoint, Interface


@dataclass(frozen=True)
class CommandSpec:
    """A command invocation with an explicit success contract.

    macOS command-line tools disagree about the meaning of a non-zero exit
    status.  In particular, ``lsof`` and diagnostic probes may return ``1``
    with useful output, while ``scutil``/``netstat`` failures must not be
    silently accepted.  Keeping that policy on each invocation prevents an
    accidental process-wide "0 or 1 means success" rule.
    """

    argv: Tuple[str, ...]
    name: str = ""
    timeout: float = 10.0
    valid_returncodes: Tuple[int, ...] = (0,)

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(str(value) for value in self.argv))
        object.__setattr__(self, "valid_returncodes", tuple(int(value) for value in self.valid_returncodes))
        if not self.argv:
            raise ValueError("command argv must not be empty")
        if self.timeout <= 0:
            raise ValueError("command timeout must be positive")
        if not self.valid_returncodes:
            raise ValueError("valid_returncodes must not be empty")

    @property
    def display_name(self) -> str:
        return self.name or Path(self.argv[0]).name


@dataclass(frozen=True)
class CommandDiagnostic:
    """Safe, structured execution metadata (never includes command output)."""

    name: str
    argv: Tuple[str, ...]
    ok: bool
    returncode: Optional[int]
    duration_ms: float
    valid_returncodes: Tuple[int, ...]
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    warning_kind: Optional[str] = None
    error_kind: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    returncode: int
    diagnostic: CommandDiagnostic


class CommandError(RuntimeError):
    def __init__(self, message: str, diagnostic: Optional[CommandDiagnostic] = None):
        super().__init__(message)
        self.diagnostic = diagnostic


def execute_command(spec: CommandSpec) -> CommandResult:
    """Execute a fully-specified command and return structured diagnostics."""

    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(spec.argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=spec.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.monotonic() - started) * 1000, 2)
        diagnostic = CommandDiagnostic(
            name=spec.display_name,
            argv=spec.argv,
            ok=False,
            returncode=None,
            duration_ms=duration_ms,
            valid_returncodes=spec.valid_returncodes,
            error_kind="timeout",
            detail=f"timed out after {spec.timeout:g}s",
        )
        raise CommandError(diagnostic.detail or "command timed out", diagnostic) from exc
    except OSError as exc:
        duration_ms = round((time.monotonic() - started) * 1000, 2)
        diagnostic = CommandDiagnostic(
            name=spec.display_name,
            argv=spec.argv,
            ok=False,
            returncode=None,
            duration_ms=duration_ms,
            valid_returncodes=spec.valid_returncodes,
            error_kind="unavailable",
            detail=str(exc),
        )
        raise CommandError(str(exc), diagnostic) from exc

    duration_ms = round((time.monotonic() - started) * 1000, 2)
    ok = completed.returncode in spec.valid_returncodes
    stderr_lower = completed.stderr.lower()
    if "operation not permitted" in stderr_lower or "permission denied" in stderr_lower:
        warning_kind = "permission-denied"
    elif completed.stderr.strip():
        warning_kind = "stderr-output"
    else:
        warning_kind = None
    detail = None
    error_message = None
    if not ok:
        error_message = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or f"command exited with {completed.returncode}"
        )
        # Diagnostics may be persisted in snapshots.  Keep raw command output
        # only on the transient exception and store a bounded status summary.
        detail = f"command exited with {completed.returncode}"
    diagnostic = CommandDiagnostic(
        name=spec.display_name,
        argv=spec.argv,
        ok=ok,
        returncode=completed.returncode,
        duration_ms=duration_ms,
        valid_returncodes=spec.valid_returncodes,
        stdout_bytes=len(completed.stdout.encode("utf-8", errors="replace")),
        stderr_bytes=len(completed.stderr.encode("utf-8", errors="replace")),
        warning_kind=warning_kind,
        error_kind=None if ok else "exit_status",
        detail=detail,
    )
    if not ok:
        raise CommandError(error_message or detail or f"command exited with {completed.returncode}", diagnostic)
    return CommandResult(completed.stdout, completed.stderr, completed.returncode, diagnostic)


def run_command(
    command: Union[Sequence[str], CommandSpec],
    timeout: Optional[float] = None,
    *,
    valid_returncodes: Sequence[int] = (0,),
    diagnostics: Optional[List[CommandDiagnostic]] = None,
) -> str:
    """Compatibility wrapper returning stdout with strict success by default.

    Existing callers can continue to pass ``Sequence[str]`` and receive a
    string.  Callers for tools with special exit semantics must opt in through
    ``valid_returncodes`` or pass a :class:`CommandSpec`.
    """

    if isinstance(command, CommandSpec):
        spec = command
        if timeout is not None:
            spec = CommandSpec(spec.argv, spec.name, timeout, spec.valid_returncodes)
    else:
        spec = CommandSpec(
            tuple(command),
            timeout=10.0 if timeout is None else timeout,
            valid_returncodes=tuple(valid_returncodes),
        )
    try:
        result = execute_command(spec)
    except CommandError as exc:
        if diagnostics is not None and exc.diagnostic is not None:
            diagnostics.append(exc.diagnostic)
        raise
    if diagnostics is not None:
        diagnostics.append(result.diagnostic)
    return result.stdout


@dataclass(frozen=True)
class ParseWarning:
    code: str
    message: str
    line_number: Optional[int] = None
    severity: str = "warning"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParseMetadata:
    parser: str
    input_lines: int = 0
    candidate_lines: int = 0
    parsed_records: int = 0
    skipped_lines: int = 0
    missing_fields: Dict[str, int] = field(default_factory=dict)
    warnings: List[ParseWarning] = field(default_factory=list)
    confidence_score: float = 1.0
    confidence: str = "unknown"

    def missing(self, field_name: str) -> None:
        self.missing_fields[field_name] = self.missing_fields.get(field_name, 0) + 1

    def warn(
        self,
        code: str,
        message: str,
        line_number: Optional[int] = None,
        severity: str = "warning",
    ) -> None:
        self.warnings.append(ParseWarning(code, message, line_number, severity))

    def finalize(self) -> None:
        if self.candidate_lines == 0:
            self.confidence_score = 1.0 if self.input_lines == 0 else 0.5
            self.confidence = "unknown"
            return
        ratio = min(1.0, self.parsed_records / self.candidate_lines)
        warning_penalty = sum(0.12 if item.severity == "error" else 0.04 for item in self.warnings)
        missing_penalty = min(0.2, sum(self.missing_fields.values()) * 0.03)
        self.confidence_score = round(max(0.0, ratio - min(0.45, warning_penalty) - missing_penalty), 3)
        if self.confidence_score >= 0.9:
            self.confidence = "high"
        elif self.confidence_score >= 0.6:
            self.confidence = "medium"
        elif self.confidence_score > 0:
            self.confidence = "low"
        else:
            self.confidence = "none"

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["warnings"] = [item.to_dict() for item in self.warnings]
        return result


ParsedValue = TypeVar("ParsedValue")


@dataclass(frozen=True)
class ParseResult(Generic[ParsedValue]):
    data: ParsedValue
    metadata: ParseMetadata


def _parse_metadata(parser: str, output: str) -> ParseMetadata:
    return ParseMetadata(parser=parser, input_lines=len(output.splitlines()))


def _finish_parse(
    data: ParsedValue,
    metadata: ParseMetadata,
    with_metadata: bool,
) -> Union[ParsedValue, ParseResult[ParsedValue]]:
    metadata.finalize()
    if with_metadata:
        return ParseResult(data=data, metadata=metadata)
    return data


def decode_command_name(value: str) -> str:
    return re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda match: bytes.fromhex(match.group(1)).decode("latin-1"),
        value,
    )


def parse_endpoint(value: str) -> Endpoint:
    value = value.strip()
    if value.startswith("["):
        closing = value.rfind("]")
        if closing >= 0:
            host = value[1:closing]
            port = value[closing + 2 :] if value[closing + 1 :].startswith(":") else None
            return Endpoint(host=host, port=port or None)
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return Endpoint(host=host, port=port or None)
    return Endpoint(host=value)


def parse_lsof(
    output: str,
    vpn_default: bool = False,
    *,
    with_metadata: bool = False,
) -> Union[List[Connection], ParseResult[List[Connection]]]:
    metadata = _parse_metadata("lsof", output)
    result: List[Connection] = []
    saw_header = False
    for line_number, line in enumerate(output.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("COMMAND") and "PID" in stripped and "NAME" in stripped:
            saw_header = True
            continue
        metadata.candidate_lines += 1
        fields = line.split(None, 8)
        if len(fields) < 9:
            metadata.skipped_lines += 1
            metadata.missing("columns")
            metadata.warn("malformed-row", "lsof row has fewer than nine columns", line_number)
            continue
        if not fields[1].isdigit():
            metadata.skipped_lines += 1
            metadata.missing("pid")
            metadata.warn("invalid-pid", "lsof PID is not numeric", line_number)
            continue
        command, pid, user, fd, family, _device, _size, protocol, name = fields
        state = ""
        state_match = re.search(r"\s+\(([^)]+)\)\s*$", name)
        if state_match:
            state = state_match.group(1)
            name = name[: state_match.start()]
        if "->" in name:
            local_raw, remote_raw = name.split("->", 1)
            remote = parse_endpoint(remote_raw)
        else:
            local_raw = name
            remote = None
        local = parse_endpoint(local_raw)
        remote_is_local = False
        if remote is not None:
            try:
                address = ipaddress.ip_address(remote.host.split("%", 1)[0])
                remote_is_local = (
                    address.is_private
                    or address.is_loopback
                    or address.is_link_local
                    or address.is_multicast
                )
            except ValueError:
                remote_is_local = remote.host in ("localhost", "*")
        if local.host in ("127.0.0.1", "::1") or (remote and remote.host in ("127.0.0.1", "::1")):
            path = "loopback"
        elif remote_is_local:
            path = "local-network"
        elif vpn_default and remote is not None:
            path = "vpn-default"
        else:
            path = "direct"
        result.append(
            Connection(
                process=decode_command_name(command),
                pid=int(pid),
                user=user,
                fd=fd,
                family=family,
                protocol=protocol.upper(),
                local=local,
                remote=remote,
                state=state,
                path=path,
            )
        )
        metadata.parsed_records += 1
    if output.strip() and not saw_header:
        metadata.missing("header")
        metadata.warn("missing-header", "lsof header was not present", severity="info")
    return _finish_parse(result, metadata, with_metadata)


def parse_routes(
    output: str,
    *,
    with_metadata: bool = False,
) -> Union[List[Dict[str, str]], ParseResult[List[Dict[str, str]]]]:
    metadata = _parse_metadata("routes", output)
    routes: List[Dict[str, str]] = []
    columns: Optional[Dict[str, int]] = None
    for line_number, line in enumerate(output.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("Destination"):
            header = stripped.split()
            normalized = {value.lower(): index for index, value in enumerate(header)}
            interface_index = next(
                (normalized[value] for value in ("netif", "interface", "iface") if value in normalized),
                None,
            )
            columns = {
                "destination": normalized.get("destination", 0),
                "gateway": normalized.get("gateway", 1),
                "flags": normalized.get("flags", 2),
            }
            if interface_index is None:
                metadata.missing("interface-column")
                metadata.warn("missing-column", "route header has no interface column", line_number)
            else:
                columns["interface"] = interface_index
            if "expire" in normalized:
                columns["expire"] = normalized["expire"]
            continue
        if columns is None or not stripped:
            continue
        # Section labels such as "Internet:" may appear between route tables.
        if stripped.endswith(":") and len(stripped.split()) == 1:
            continue
        metadata.candidate_lines += 1
        fields = line.split()
        required_indices = [columns.get(value, -1) for value in ("destination", "gateway", "flags", "interface")]
        if -1 in required_indices or max(required_indices) >= len(fields):
            metadata.skipped_lines += 1
            metadata.missing("route-fields")
            metadata.warn("malformed-row", "route row does not match its header", line_number)
            continue
        routes.append(
            {
                "destination": fields[columns["destination"]],
                "gateway": fields[columns["gateway"]],
                "flags": fields[columns["flags"]],
                "interface": fields[columns["interface"]],
                "expire": fields[columns["expire"]] if columns.get("expire", len(fields)) < len(fields) else "",
            }
        )
        metadata.parsed_records += 1
    if output.strip() and columns is None:
        metadata.missing("header")
        metadata.warn("missing-header", "routing table header was not found", severity="error")
    return _finish_parse(routes, metadata, with_metadata)


def parse_ifconfig(
    output: str,
    *,
    with_metadata: bool = False,
) -> Union[List[Interface], ParseResult[List[Interface]]]:
    metadata = _parse_metadata("ifconfig", output)
    interfaces: List[Interface] = []
    current: Optional[Interface] = None
    current_line: Optional[int] = None

    def append_current() -> None:
        nonlocal current
        if current is None:
            return
        if not current.flags:
            metadata.missing("flags")
            metadata.warn("missing-flags", f"interface {current.name} has no parsed flags", current_line, "info")
        if current.mtu is None:
            metadata.missing("mtu")
        interfaces.append(current)
        metadata.parsed_records += 1

    for line_number, line in enumerate(output.splitlines(), 1):
        header_match = re.match(r"^([A-Za-z0-9_.:-]+):(?:\s|$)", line)
        if header_match and not line[0].isspace():
            if current:
                append_current()
            metadata.candidate_lines += 1
            name = header_match.group(1)
            flags_match = re.search(r"flags=[^<]*<([^>]*)>", line)
            flags = [value for value in flags_match.group(1).split(",") if value] if flags_match else []
            mtu_match = re.search(r"\bmtu\s+(\d+)", line)
            current = Interface(
                name=name,
                flags=flags,
                mtu=int(mtu_match.group(1)) if mtu_match else None,
            )
            current_line = line_number
            continue
        if current is None:
            if line.strip() and not line.strip().endswith(":"):
                metadata.skipped_lines += 1
            continue
        stripped = line.strip()
        if stripped.startswith("inet "):
            fields = stripped.split()
            if len(fields) >= 2:
                current.ipv4.append(fields[1])
            else:
                metadata.missing("ipv4-address")
                metadata.warn("malformed-address", "inet row has no address", line_number)
        elif stripped.startswith("inet6 "):
            fields = stripped.split()
            if len(fields) >= 2:
                current.ipv6.append(fields[1])
            else:
                metadata.missing("ipv6-address")
                metadata.warn("malformed-address", "inet6 row has no address", line_number)
        elif stripped.startswith("status:"):
            current.status = stripped.split(":", 1)[1].strip()
    if current:
        append_current()
    if output.strip() and not interfaces:
        metadata.missing("interface-records")
        metadata.warn("no-records", "no interface headers were parsed", severity="error")
    return _finish_parse(interfaces, metadata, with_metadata)


def parse_scutil_dns(
    output: str,
    *,
    with_metadata: bool = False,
) -> Union[List[Dict[str, Any]], ParseResult[List[Dict[str, Any]]]]:
    metadata = _parse_metadata("scutil-dns", output)
    resolvers: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    current_line: Optional[int] = None

    def append_current() -> None:
        nonlocal current
        if current is None:
            return
        if not current["nameservers"]:
            metadata.missing("nameservers")
            metadata.warn(
                "resolver-without-nameserver",
                f"resolver #{current['id']} has no nameserver",
                current_line,
                "info",
            )
        resolvers.append(current)
        metadata.parsed_records += 1

    for line_number, raw in enumerate(output.splitlines(), 1):
        line = raw.strip()
        match = re.match(r"resolver #(\d+)", line)
        if match:
            if current:
                append_current()
            metadata.candidate_lines += 1
            current = {"id": int(match.group(1)), "nameservers": [], "search_domains": []}
            current_line = line_number
            continue
        if current is None or ":" not in line:
            if line.lower().startswith("no dns configuration"):
                metadata.warn("no-configuration", "macOS reports no DNS configuration", line_number, "info")
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if key.startswith("nameserver"):
            current["nameservers"].append(value)
        elif key.startswith("search domain"):
            current["search_domains"].append(value)
        elif key in ("if_index", "flags", "reach", "order"):
            current[key] = value
    if current:
        append_current()
    if output.strip() and not resolvers and not any(item.code == "no-configuration" for item in metadata.warnings):
        metadata.missing("resolver-records")
        metadata.warn("no-records", "no resolver blocks were parsed", severity="error")
    return _finish_parse(resolvers, metadata, with_metadata)


def parse_interface_counters(
    output: str,
    *,
    with_metadata: bool = False,
) -> Union[Dict[str, Dict[str, int]], ParseResult[Dict[str, Dict[str, int]]]]:
    """Parse `netstat -ibdn` and aggregate duplicate address rows per interface."""
    metadata = _parse_metadata("interface-counters", output)
    counters: Dict[str, Dict[str, int]] = {}
    header: Optional[List[str]] = None
    for line_number, line in enumerate(output.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "Name" and "Ibytes" in fields and "Obytes" in fields:
            header = fields
            continue
        if header is None:
            continue
        metadata.candidate_lines += 1
        counter_columns = [
            value
            for value in ("Ipkts", "Ierrs", "Ibytes", "Opkts", "Oerrs", "Obytes", "Coll", "Drop")
            if value in header
        ]
        if len(fields) < len(counter_columns) + 1:
            metadata.skipped_lines += 1
            metadata.missing("columns")
            metadata.warn("malformed-row", "counter row has too few metric columns", line_number)
            continue
        # Network/address fields differ across macOS releases and address
        # families.  Counter fields are stable at the right edge of each row,
        # so align from the tail instead of discarding a short descriptor row.
        row = dict(zip(counter_columns, fields[-len(counter_columns) :]))
        name = fields[0]
        if not name:
            metadata.skipped_lines += 1
            metadata.missing("name")
            continue
        values = counters.setdefault(
            name,
            {
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_packets": 0,
                "tx_packets": 0,
                "rx_errors": 0,
                "tx_errors": 0,
                "drops": 0,
            },
        )
        mapping = {
            "Ibytes": "rx_bytes",
            "Obytes": "tx_bytes",
            "Ipkts": "rx_packets",
            "Opkts": "tx_packets",
            "Ierrs": "rx_errors",
            "Oerrs": "tx_errors",
            "Drop": "drops",
        }
        for source, target in mapping.items():
            try:
                # Each interface may have one row per address. The counters repeat,
                # so max avoids multiplying totals.
                values[target] = max(values[target], int(row.get(source, "0")))
            except ValueError:
                raw_value = row.get(source, "")
                if raw_value not in ("", "-"):
                    metadata.warn("invalid-counter", f"{source} is not numeric", line_number)
                continue
        metadata.parsed_records += 1
    if output.strip() and header is None:
        metadata.missing("header")
        metadata.warn("missing-header", "counter table header was not found", severity="error")
    return _finish_parse(counters, metadata, with_metadata)


def parse_scutil_proxy(output: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for raw in output.splitlines():
        line = raw.strip()
        match = re.match(r"([^:={]+)\s*:\s*(.+)", line)
        if not match:
            continue
        key, value = match.group(1).strip(), match.group(2).strip()
        if value.isdigit():
            result[key] = int(value)
        else:
            result[key] = value
    return result


def parse_route_get(output: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if key in ("route to", "destination", "gateway", "interface", "flags", "recvpipe", "sendpipe", "mtu"):
            result[key.replace(" ", "_")] = value
    return result


def parse_arp(
    output: str,
    *,
    with_metadata: bool = False,
) -> Union[List[Dict[str, str]], ParseResult[List[Dict[str, str]]]]:
    metadata = _parse_metadata("arp", output)
    values: List[Dict[str, str]] = []
    pattern = re.compile(
        r"^(?P<name>.*?)\s*\((?P<address>[^)]+)\)\s+at\s+"
        r"(?P<mac>\([^)]*\)|\S+)\s+on\s+(?P<interface>\S+)(?P<rest>.*)$"
    )
    for line_number, line in enumerate(output.splitlines(), 1):
        if not line.strip():
            continue
        metadata.candidate_lines += 1
        match = pattern.match(line.strip())
        if not match:
            metadata.skipped_lines += 1
            metadata.missing("neighbor-fields")
            metadata.warn("malformed-row", "ARP row did not match the macOS format", line_number)
            continue
        item = match.groupdict()
        item["family"] = "IPv4"
        item["state"] = item.pop("rest").strip()
        values.append(item)
        metadata.parsed_records += 1
    return _finish_parse(values, metadata, with_metadata)


def parse_ndp(
    output: str,
    *,
    with_metadata: bool = False,
) -> Union[List[Dict[str, str]], ParseResult[List[Dict[str, str]]]]:
    metadata = _parse_metadata("ndp", output)
    values: List[Dict[str, str]] = []
    started = False
    for line_number, line in enumerate(output.splitlines(), 1):
        if line.lstrip().startswith("Neighbor"):
            started = True
            continue
        if not started or not line.strip():
            continue
        metadata.candidate_lines += 1
        fields = line.split()
        if len(fields) < 3:
            metadata.skipped_lines += 1
            metadata.missing("neighbor-fields")
            metadata.warn("malformed-row", "NDP row has fewer than three fields", line_number)
            continue
        address, mac, interface = fields[:3]
        if ":" not in address:
            metadata.skipped_lines += 1
            metadata.missing("address")
            metadata.warn("invalid-address", "NDP neighbor is not an IPv6 address", line_number)
            continue
        values.append(
            {
                "name": "?",
                "address": address,
                "mac": mac,
                "interface": interface,
                "family": "IPv6",
                "state": " ".join(fields[3:]),
            }
        )
        metadata.parsed_records += 1
    if output.strip() and not started:
        metadata.missing("header")
        metadata.warn("missing-header", "NDP table header was not found", severity="error")
    return _finish_parse(values, metadata, with_metadata)


def fallback_resolvers() -> List[Dict[str, Any]]:
    path = Path("/etc/resolv.conf")
    nameservers: List[str] = []
    search_domains: List[str] = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                nameservers.append(fields[1])
            elif len(fields) >= 2 and fields[0] in ("search", "domain"):
                search_domains.extend(fields[1:])
    except OSError:
        pass
    if not nameservers and not search_domains:
        return []
    return [{"id": 1, "nameservers": nameservers, "search_domains": search_domains, "source": "/etc/resolv.conf"}]


@dataclass(frozen=True)
class CapabilityStatus:
    name: str
    available: bool
    tools: Tuple[str, ...]
    missing_tools: Tuple[str, ...]
    description: str
    requires_root: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_CAPABILITY_DEFINITIONS: Dict[str, Tuple[Tuple[str, ...], str, bool, bool]] = {
    "connections": (("/usr/sbin/lsof",), "Process-owned TCP and UDP sockets", False, True),
    "routes": (("/usr/sbin/netstat", "/sbin/route"), "Routing tables and effective routes", False, True),
    "interfaces": (("/sbin/ifconfig",), "Interface addresses, flags, and status", False, True),
    "dns": (("/usr/sbin/scutil",), "macOS resolver configuration", False, True),
    # At least one address-family neighbor tool is sufficient for partial data.
    "neighbors": (("/usr/sbin/arp", "/usr/sbin/ndp"), "IPv4/IPv6 neighbor cache", False, False),
    "wifi": (
        ("/usr/sbin/system_profiler", "/usr/sbin/networksetup"),
        "Wi-Fi adapter and association details",
        False,
        True,
    ),
    "wifi_deep": (("/usr/bin/wdutil",), "Detailed Wi-Fi radio diagnostics", True, True),
    "bluetooth": (("/usr/sbin/system_profiler",), "Bluetooth controller and device inventory", False, True),
    "network_quality": (("/usr/bin/networkQuality",), "Native responsiveness and throughput probe", False, True),
    "packet_capture": (("/usr/sbin/tcpdump",), "Packet capture metadata", True, True),
}


class MacOSAdapter:
    def __init__(self) -> None:
        self._command_diagnostics: List[CommandDiagnostic] = []
        self._parser_diagnostics: List[ParseMetadata] = []

    def _run(self, spec: CommandSpec) -> str:
        return run_command(spec, diagnostics=self._command_diagnostics)

    def _parsed(self, result: ParseResult[ParsedValue]) -> ParsedValue:
        self._parser_diagnostics.append(result.metadata)
        return result.data

    def command_diagnostics(self, clear: bool = False) -> List[Dict[str, Any]]:
        values = [item.to_dict() for item in self._command_diagnostics]
        if clear:
            self._command_diagnostics.clear()
        return values

    def parser_diagnostics(self, clear: bool = False) -> List[Dict[str, Any]]:
        values = [item.to_dict() for item in self._parser_diagnostics]
        if clear:
            self._parser_diagnostics.clear()
        return values

    def clear_diagnostics(self) -> None:
        self._command_diagnostics.clear()
        self._parser_diagnostics.clear()

    def capabilities(self) -> Dict[str, Any]:
        statuses: Dict[str, Dict[str, Any]] = {}
        tools: Dict[str, Dict[str, Any]] = {}
        for name, (paths, description, requires_root, require_all) in _CAPABILITY_DEFINITIONS.items():
            missing = tuple(path for path in paths if not (Path(path).is_file() and os.access(path, os.X_OK)))
            available = not missing if require_all else len(missing) < len(paths)
            status = CapabilityStatus(name, available, paths, missing, description, requires_root)
            statuses[name] = status.to_dict()
            for path in paths:
                tools.setdefault(
                    path,
                    {
                        "path": path,
                        "available": Path(path).is_file() and os.access(path, os.X_OK),
                    },
                )
        return {
            "schema_version": 1,
            "platform": sys.platform,
            "is_macos": sys.platform == "darwin",
            "effective_uid": os.geteuid(),
            "capabilities": statuses,
            "tools": tools,
        }

    def routes(self) -> List[Dict[str, str]]:
        output = self._run(CommandSpec(("/usr/sbin/netstat", "-rn", "-f", "inet"), "routes.ipv4"))
        return self._parsed(parse_routes(output, with_metadata=True))

    def default_routes(self) -> List[Dict[str, str]]:
        return [route for route in self.routes() if route["destination"] == "default"]

    def interfaces(self) -> List[Interface]:
        output = self._run(CommandSpec(("/sbin/ifconfig",), "interfaces"))
        return self._parsed(parse_ifconfig(output, with_metadata=True))

    def interface_counters(self) -> Dict[str, Dict[str, int]]:
        try:
            output = self._run(CommandSpec(("/usr/sbin/netstat", "-ibdn"), "interface-counters"))
            return self._parsed(parse_interface_counters(output, with_metadata=True))
        except CommandError:
            return {}

    def proxy_config(self) -> Dict[str, Any]:
        try:
            return parse_scutil_proxy(self._run(CommandSpec(("/usr/sbin/scutil", "--proxy"), "proxy-config")))
        except CommandError:
            return {}

    def route_for(self, target: str) -> Dict[str, str]:
        if not re.fullmatch(r"[A-Za-z0-9.:%_-]+", target):
            raise ValueError("invalid route target")
        return parse_route_get(self._run(CommandSpec(("/sbin/route", "-n", "get", target), "route-effective")))

    def neighbors(self) -> List[Dict[str, str]]:
        values: List[Dict[str, str]] = []
        try:
            output = self._run(
                CommandSpec(("/usr/sbin/arp", "-an"), "neighbors.ipv4", valid_returncodes=(0, 1))
            )
            values.extend(self._parsed(parse_arp(output, with_metadata=True)))
        except CommandError:
            pass
        try:
            output = self._run(
                CommandSpec(("/usr/sbin/ndp", "-an"), "neighbors.ipv6", valid_returncodes=(0, 1))
            )
            values.extend(self._parsed(parse_ndp(output, with_metadata=True)))
        except CommandError:
            pass
        return values

    def connections(self) -> List[Connection]:
        vpn_default = any(
            route["interface"].startswith(("utun", "tun", "ppp", "wg"))
            for route in self.default_routes()
        )
        output = self._run(
            CommandSpec(
                ("/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP"),
                "connections",
                timeout=20,
                valid_returncodes=(0, 1),
            )
        )
        return self._parsed(parse_lsof(output, vpn_default=vpn_default, with_metadata=True))

    def dns_resolvers(self) -> List[Dict[str, Any]]:
        try:
            output = self._run(CommandSpec(("/usr/sbin/scutil", "--dns"), "dns-resolvers"))
            resolvers = self._parsed(parse_scutil_dns(output, with_metadata=True))
        except CommandError:
            resolvers = []
        return resolvers or fallback_resolvers()

    def vpn_status(self) -> Dict[str, Any]:
        interfaces = [interface for interface in self.interfaces() if interface.is_vpn and "UP" in interface.flags]
        defaults = self.default_routes()
        vpn_defaults = [route for route in defaults if route["interface"].startswith(("utun", "tun", "ppp", "wg"))]
        return {
            "active": bool(interfaces),
            "full_tunnel_likely": bool(vpn_defaults),
            "interfaces": [interface.to_dict() for interface in interfaces],
            "default_routes": defaults,
            "warnings": self._vpn_warnings(interfaces, vpn_defaults),
        }

    @staticmethod
    def _vpn_warnings(interfaces: Iterable[Interface], vpn_defaults: List[Dict[str, str]]) -> List[str]:
        warnings: List[str] = []
        if list(interfaces) and not vpn_defaults:
            warnings.append(
                "VPN interfaces exist, but the IPv4 default route does not use them "
                "(split tunnel or idle tunnel)."
            )
        if vpn_defaults and not any(interface.ipv4 for interface in interfaces):
            warnings.append("The VPN default route is active, but its interface has no visible IPv4 address.")
        return warnings

    def wifi_info(self, deep: bool = False) -> Dict[str, Any]:
        data = json.loads(
            self._run(
                CommandSpec(
                    ("/usr/sbin/system_profiler", "SPAirPortDataType", "-json"),
                    "wifi-profiler",
                    timeout=30,
                )
            )
        )
        result: Dict[str, Any] = {"profiler": data.get("SPAirPortDataType", [])}
        interfaces = [
            item.to_dict()
            for item in self.interfaces()
            if item.name.startswith(("en", "awdl", "llw", "ap"))
        ]
        result["interfaces"] = interfaces
        try:
            current = self._run(
                CommandSpec(("/usr/sbin/networksetup", "-getairportnetwork", "en0"), "wifi-association")
            ).strip()
            if current:
                result["current_network"] = current
        except CommandError as exc:
            result["networksetup_error"] = str(exc)
        if deep:
            if os.geteuid() == 0:
                try:
                    result["wdutil"] = self._run(
                        CommandSpec(("/usr/bin/wdutil", "info"), "wifi-deep", timeout=30)
                    ).strip()
                except CommandError as exc:
                    result["wdutil_error"] = str(exc)
            else:
                result["deep_note"] = "Run `sudo wirescope wifi --deep` to include wdutil radio/channel diagnostics."
        return result

    def bluetooth_info(self) -> Dict[str, Any]:
        data = json.loads(
            self._run(
                CommandSpec(
                    ("/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"),
                    "bluetooth-profiler",
                    timeout=30,
                )
            )
        )
        return {"raw": data.get("SPBluetoothDataType", [])}

    def native_network_quality(self, interface: Optional[str] = None, max_runtime: int = 20) -> Dict[str, Any]:
        command = ["/usr/bin/networkQuality", "-c", "-M", str(max_runtime)]
        if interface:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface):
                raise ValueError("invalid interface name")
            command.extend(["-I", interface])
        output = self._run(
            CommandSpec(tuple(command), "network-quality", timeout=max_runtime + 10)
        )
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {"raw": output.strip()}

    def snapshot(self) -> Dict[str, Any]:
        started = time.monotonic()
        command_cursor = len(self._command_diagnostics)
        parser_cursor = len(self._parser_diagnostics)
        connections = self.connections()
        interfaces = self.interfaces()
        routes = self.routes()
        dns = self.dns_resolvers()
        vpn = self.vpn_status()
        proxy = self.proxy_config()
        interface_counters = self.interface_counters()
        collection_ms = round((time.monotonic() - started) * 1000, 2)
        return {
            "connections": connections,
            "interfaces": interfaces,
            "routes": routes,
            "dns": dns,
            "vpn": vpn,
            "proxy": proxy,
            "interface_counters": interface_counters,
            "collection_ms": collection_ms,
            "collection": {
                "duration_ms": collection_ms,
                "command_diagnostics": [
                    item.to_dict() for item in self._command_diagnostics[command_cursor:]
                ],
                "parser_diagnostics": [
                    item.to_dict() for item in self._parser_diagnostics[parser_cursor:]
                ],
            },
            "capabilities": self.capabilities(),
        }

    @staticmethod
    def resolve(domain: str) -> List[Tuple[str, str]]:
        values = set()
        for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(domain, None):
            label = "IPv6" if family == socket.AF_INET6 else "IPv4"
            values.add((label, sockaddr[0]))
        return sorted(values)
