from __future__ import annotations

import json
import ipaddress
import re
import socket
import subprocess
import time
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Connection, Endpoint, Interface


class CommandError(RuntimeError):
    pass


def run_command(command: Sequence[str], timeout: float = 10.0) -> str:
    try:
        completed = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CommandError(str(exc)) from exc
    if completed.returncode not in (0, 1):
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise CommandError(detail or f"command exited with {completed.returncode}")
    return completed.stdout


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


def parse_lsof(output: str, vpn_default: bool = False) -> List[Connection]:
    result: List[Connection] = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("COMMAND"):
            continue
        fields = line.split(None, 8)
        if len(fields) < 9 or not fields[1].isdigit():
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
                remote_is_local = address.is_private or address.is_loopback or address.is_link_local or address.is_multicast
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
    return result


def parse_routes(output: str) -> List[Dict[str, str]]:
    routes: List[Dict[str, str]] = []
    started = False
    for line in output.splitlines():
        if line.startswith("Destination"):
            started = True
            continue
        if not started or not line.strip():
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        routes.append(
            {
                "destination": fields[0],
                "gateway": fields[1],
                "flags": fields[2],
                "interface": fields[3],
                "expire": fields[4] if len(fields) > 4 else "",
            }
        )
    return routes


def parse_ifconfig(output: str) -> List[Interface]:
    interfaces: List[Interface] = []
    current: Optional[Interface] = None
    for line in output.splitlines():
        if line and not line[0].isspace() and ":" in line:
            if current:
                interfaces.append(current)
            name = line.split(":", 1)[0]
            flags_match = re.search(r"flags=[^<]*<([^>]*)>", line)
            flags = flags_match.group(1).split(",") if flags_match else []
            mtu_match = re.search(r"\bmtu\s+(\d+)", line)
            current = Interface(
                name=name,
                flags=flags,
                mtu=int(mtu_match.group(1)) if mtu_match else None,
            )
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("inet "):
            current.ipv4.append(stripped.split()[1])
        elif stripped.startswith("inet6 "):
            current.ipv6.append(stripped.split()[1])
        elif stripped.startswith("status:"):
            current.status = stripped.split(":", 1)[1].strip()
    if current:
        interfaces.append(current)
    return interfaces


def parse_scutil_dns(output: str) -> List[Dict[str, Any]]:
    resolvers: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw in output.splitlines():
        line = raw.strip()
        match = re.match(r"resolver #(\d+)", line)
        if match:
            if current:
                resolvers.append(current)
            current = {"id": int(match.group(1)), "nameservers": [], "search_domains": []}
            continue
        if current is None or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if key.startswith("nameserver"):
            current["nameservers"].append(value)
        elif key.startswith("search domain"):
            current["search_domains"].append(value)
        elif key in ("if_index", "flags", "reach", "order"):
            current[key] = value
    if current:
        resolvers.append(current)
    return resolvers


def parse_interface_counters(output: str) -> Dict[str, Dict[str, int]]:
    """Parse `netstat -ibdn` and aggregate duplicate address rows per interface."""
    counters: Dict[str, Dict[str, int]] = {}
    header: Optional[List[str]] = None
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "Name" and "Ibytes" in fields and "Obytes" in fields:
            header = fields
            continue
        if header is None or len(fields) < len(header):
            continue
        row = dict(zip(header, fields))
        name = row.get("Name", "")
        if not name:
            continue
        values = counters.setdefault(
            name,
            {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0, "rx_errors": 0, "tx_errors": 0, "drops": 0},
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
                continue
    return counters


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


def parse_arp(output: str) -> List[Dict[str, str]]:
    values = []
    pattern = re.compile(r"^(?P<name>.*?)\s*\((?P<address>[^)]+)\)\s+at\s+(?P<mac>\S+)\s+on\s+(?P<interface>\S+)(?P<rest>.*)$")
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        item = match.groupdict()
        item["family"] = "IPv4"
        item["state"] = item.pop("rest").strip()
        values.append(item)
    return values


def parse_ndp(output: str) -> List[Dict[str, str]]:
    values = []
    started = False
    for line in output.splitlines():
        if line.startswith("Neighbor"):
            started = True
            continue
        if not started or not line.strip():
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        values.append(
            {
                "name": "?",
                "address": fields[0],
                "mac": fields[1],
                "interface": fields[2],
                "family": "IPv6",
                "state": " ".join(fields[3:]),
            }
        )
    return values


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


class MacOSAdapter:
    def routes(self) -> List[Dict[str, str]]:
        return parse_routes(run_command(["/usr/sbin/netstat", "-rn", "-f", "inet"]))

    def default_routes(self) -> List[Dict[str, str]]:
        return [route for route in self.routes() if route["destination"] == "default"]

    def interfaces(self) -> List[Interface]:
        return parse_ifconfig(run_command(["/sbin/ifconfig"]))

    def interface_counters(self) -> Dict[str, Dict[str, int]]:
        try:
            return parse_interface_counters(run_command(["/usr/sbin/netstat", "-ibdn"]))
        except CommandError:
            return {}

    def proxy_config(self) -> Dict[str, Any]:
        try:
            return parse_scutil_proxy(run_command(["/usr/sbin/scutil", "--proxy"]))
        except CommandError:
            return {}

    def route_for(self, target: str) -> Dict[str, str]:
        if not re.fullmatch(r"[A-Za-z0-9.:%_-]+", target):
            raise ValueError("invalid route target")
        return parse_route_get(run_command(["/sbin/route", "-n", "get", target]))

    def neighbors(self) -> List[Dict[str, str]]:
        values: List[Dict[str, str]] = []
        try:
            values.extend(parse_arp(run_command(["/usr/sbin/arp", "-an"])))
        except CommandError:
            pass
        try:
            values.extend(parse_ndp(run_command(["/usr/sbin/ndp", "-an"])))
        except CommandError:
            pass
        return values

    def connections(self) -> List[Connection]:
        vpn_default = any(route["interface"].startswith(("utun", "tun", "ppp", "wg")) for route in self.default_routes())
        output = run_command(["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP"], timeout=20)
        return parse_lsof(output, vpn_default=vpn_default)

    def dns_resolvers(self) -> List[Dict[str, Any]]:
        try:
            resolvers = parse_scutil_dns(run_command(["/usr/sbin/scutil", "--dns"]))
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
            warnings.append("VPN interfaces exist, but the IPv4 default route does not use them (split tunnel or idle tunnel).")
        if vpn_defaults and not any(interface.ipv4 for interface in interfaces):
            warnings.append("The VPN default route is active, but its interface has no visible IPv4 address.")
        return warnings

    def wifi_info(self, deep: bool = False) -> Dict[str, Any]:
        data = json.loads(run_command(["/usr/sbin/system_profiler", "SPAirPortDataType", "-json"], timeout=30))
        result: Dict[str, Any] = {"profiler": data.get("SPAirPortDataType", [])}
        interfaces = [item.to_dict() for item in self.interfaces() if item.name.startswith(("en", "awdl", "llw", "ap"))]
        result["interfaces"] = interfaces
        try:
            current = run_command(["/usr/sbin/networksetup", "-getairportnetwork", "en0"]).strip()
            if current:
                result["current_network"] = current
        except CommandError as exc:
            result["networksetup_error"] = str(exc)
        if deep:
            if os.geteuid() == 0:
                try:
                    result["wdutil"] = run_command(["/usr/bin/wdutil", "info"], timeout=30).strip()
                except CommandError as exc:
                    result["wdutil_error"] = str(exc)
            else:
                result["deep_note"] = "Run `sudo wirescope wifi --deep` to include wdutil radio/channel diagnostics."
        return result

    def bluetooth_info(self) -> Dict[str, Any]:
        data = json.loads(run_command(["/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"], timeout=30))
        return {"raw": data.get("SPBluetoothDataType", [])}

    def native_network_quality(self, interface: Optional[str] = None, max_runtime: int = 20) -> Dict[str, Any]:
        command = ["/usr/bin/networkQuality", "-c", "-M", str(max_runtime)]
        if interface:
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface):
                raise ValueError("invalid interface name")
            command.extend(["-I", interface])
        output = run_command(command, timeout=max_runtime + 10)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {"raw": output.strip()}

    def snapshot(self) -> Dict[str, Any]:
        started = time.monotonic()
        connections = self.connections()
        interfaces = self.interfaces()
        return {
            "connections": connections,
            "interfaces": interfaces,
            "routes": self.routes(),
            "dns": self.dns_resolvers(),
            "vpn": self.vpn_status(),
            "proxy": self.proxy_config(),
            "interface_counters": self.interface_counters(),
            "collection_ms": round((time.monotonic() - started) * 1000, 2),
        }

    @staticmethod
    def resolve(domain: str) -> List[Tuple[str, str]]:
        values = set()
        for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(domain, None):
            label = "IPv6" if family == socket.AF_INET6 else "IPv4"
            values.add((label, sockaddr[0]))
        return sorted(values)
