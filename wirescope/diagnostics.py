from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .macos import CommandError, MacOSAdapter, parse_routes, run_command
from .models import utc_now
from .quality import quality_report
from .redact import safe_error


DNS_TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "HTTPS": 65}
DNS_TYPE_NAMES = {value: key for key, value in DNS_TYPES.items()}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    recommendation: str = ""

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def encode_dns_name(domain: str) -> bytes:
    labels = domain.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label in {domain!r}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def decode_dns_name(packet: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    if depth > 20:
        raise ValueError("DNS compression pointer loop")
    labels: List[str] = []
    original_next: Optional[int] = None
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if original_next is None:
                original_next = offset + 2
            pointed, _ = decode_dns_name(packet, pointer, depth + 1)
            labels.append(pointed)
            offset += 2
            break
        offset += 1
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(filter(None, labels)), original_next if original_next is not None else offset


def parse_dns_response(packet: bytes, expected_id: int) -> Dict[str, Any]:
    if len(packet) < 12:
        raise ValueError("DNS response is shorter than its header")
    query_id, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", packet[:12])
    if query_id != expected_id:
        raise ValueError("DNS response ID does not match query")
    offset = 12
    for _ in range(questions):
        _name, offset = decode_dns_name(packet, offset)
        offset += 4
    records: List[Dict[str, Any]] = []
    for section, count in (("answer", answers), ("authority", authority), ("additional", additional)):
        for _ in range(count):
            name, offset = decode_dns_name(packet, offset)
            if offset + 10 > len(packet):
                raise ValueError("truncated DNS resource record")
            record_type, record_class, ttl, length = struct.unpack("!HHIH", packet[offset : offset + 10])
            offset += 10
            rdata_offset = offset
            rdata = packet[offset : offset + length]
            offset += length
            value: Any = rdata.hex()
            try:
                if record_type == 1 and length == 4:
                    value = socket.inet_ntop(socket.AF_INET, rdata)
                elif record_type == 28 and length == 16:
                    value = socket.inet_ntop(socket.AF_INET6, rdata)
                elif record_type in (2, 5, 12):
                    value, _ = decode_dns_name(packet, rdata_offset)
                elif record_type == 15 and length >= 3:
                    preference = struct.unpack("!H", rdata[:2])[0]
                    exchange, _ = decode_dns_name(packet, rdata_offset + 2)
                    value = {"preference": preference, "exchange": exchange}
                elif record_type == 16:
                    parts = []
                    cursor = 0
                    while cursor < len(rdata):
                        size = rdata[cursor]
                        cursor += 1
                        parts.append(rdata[cursor : cursor + size].decode("utf-8", errors="replace"))
                        cursor += size
                    value = parts
            except (OSError, ValueError, struct.error):
                value = rdata.hex()
            records.append(
                {
                    "section": section,
                    "name": name,
                    "type": DNS_TYPE_NAMES.get(record_type, str(record_type)),
                    "class": record_class,
                    "ttl": ttl,
                    "value": value,
                }
            )
    return {
        "rcode": flags & 0x0F,
        "rcode_name": DNS_RCODES.get(flags & 0x0F, f"RCODE_{flags & 0x0F}"),
        "authoritative": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "recursion_available": bool(flags & 0x0080),
        "authenticated_data": bool(flags & 0x0020),
        "counts": {"questions": questions, "answers": answers, "authority": authority, "additional": additional},
        "records": records,
        "response_bytes": len(packet),
    }


def dns_query(domain: str, server: str, query_type: str = "A", timeout: float = 2.0) -> Dict[str, Any]:
    query_type = query_type.upper()
    if query_type not in DNS_TYPES:
        raise ValueError(f"unsupported DNS type {query_type}; choose {', '.join(DNS_TYPES)}")
    query_id = random.SystemRandom().randrange(1, 65536)
    message = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encode_dns_name(domain) + struct.pack("!HH", DNS_TYPES[query_type], 1)
    started = time.monotonic()
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            destination: Any = (server, 53, 0, 0) if family == socket.AF_INET6 else (server, 53)
            client.sendto(message, destination)
            packet, peer = client.recvfrom(65535)
        parsed = parse_dns_response(packet, query_id)
        parsed.update(
            {
                "ok": parsed["rcode"] == 0,
                "domain": domain,
                "query_type": query_type,
                "server": server,
                "peer": peer[0],
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            }
        )
        return parsed
    except (OSError, ValueError, struct.error) as exc:
        return {
            "ok": False,
            "domain": domain,
            "query_type": query_type,
            "server": server,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
            "error": safe_error(str(exc)),
            "records": [],
        }


def dns_compare(domain: str, servers: Sequence[str], query_type: str = "A", timeout: float = 2.0) -> Dict[str, Any]:
    results = [dns_query(domain, server, query_type=query_type, timeout=timeout) for server in servers]
    successful = [item for item in results if item.get("ok")]
    fastest = min(successful, key=lambda item: item["duration_ms"])["server"] if successful else None
    answer_sets: Dict[str, List[str]] = {}
    for item in successful:
        answer_sets[item["server"]] = sorted(str(record["value"]) for record in item["records"] if record["section"] == "answer")
    return {
        "timestamp": utc_now(),
        "domain": domain,
        "query_type": query_type,
        "fastest": fastest,
        "answers_differ": len({tuple(value) for value in answer_sets.values()}) > 1,
        "results": results,
    }


def flatten_certificate_name(value: Iterable[Iterable[Tuple[str, str]]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for group in value:
        for key, item in group:
            result[key] = item
    return result


def inspect_tls(domain: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    started = time.monotonic()
    result: Dict[str, Any] = {"timestamp": utc_now(), "domain": domain, "port": port, "ok": False}
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, port, type=socket.SOCK_STREAM)})
        resolved = time.monotonic()
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            connected = time.monotonic()
            peer = raw.getpeername()
            with context.wrap_socket(raw, server_hostname=domain) as secured:
                finished = time.monotonic()
                certificate = secured.getpeercert()
                cipher = secured.cipher()
                expires_raw = certificate.get("notAfter")
                expires_at = ssl.cert_time_to_seconds(expires_raw) if expires_raw else None
                days_remaining = round((expires_at - time.time()) / 86400, 1) if expires_at else None
                result.update(
                    {
                        "ok": True,
                        "addresses": addresses,
                        "peer": {"address": peer[0], "port": peer[1]},
                        "timing_ms": {
                            "dns": round((resolved - started) * 1000, 2),
                            "tcp": round((connected - resolved) * 1000, 2),
                            "tls": round((finished - connected) * 1000, 2),
                            "total": round((finished - started) * 1000, 2),
                        },
                        "tls_version": secured.version(),
                        "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
                        "alpn": secured.selected_alpn_protocol(),
                        "session_reused": secured.session_reused,
                        "certificate": {
                            "subject": flatten_certificate_name(certificate.get("subject", ())),
                            "issuer": flatten_certificate_name(certificate.get("issuer", ())),
                            "serial_number": certificate.get("serialNumber"),
                            "version": certificate.get("version"),
                            "not_before": certificate.get("notBefore"),
                            "not_after": expires_raw,
                            "days_remaining": days_remaining,
                            "subject_alt_names": [item[1] for item in certificate.get("subjectAltName", ())],
                            "ocsp": certificate.get("OCSP"),
                            "ca_issuers": certificate.get("caIssuers"),
                            "crl_distribution_points": certificate.get("crlDistributionPoints"),
                        },
                    }
                )
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = safe_error(str(exc))
        result["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def trace_route(target: str, max_hops: int = 20, wait: float = 1.0) -> Dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9.:%_-]+", target):
        raise ValueError("invalid traceroute target")
    started = time.monotonic()
    command = ["/usr/sbin/traceroute", "-n", "-m", str(max_hops), "-w", str(wait), target]
    try:
        output = run_command(
            command,
            timeout=max(10, max_hops * wait * 4),
            valid_returncodes=(0, 1),
        )
        error = None
    except CommandError as exc:
        output = ""
        error = safe_error(str(exc))
    hops = []
    for line in output.splitlines()[1:]:
        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if not match:
            continue
        hop_number = int(match.group(1))
        rest = match.group(2)
        addresses = re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|[0-9a-fA-F:]{2,}", rest)
        timings = [float(value) for value in re.findall(r"([\d.]+)\s*ms", rest)]
        hops.append(
            {
                "hop": hop_number,
                "addresses": list(dict.fromkeys(addresses)),
                "samples_ms": timings,
                "average_ms": round(sum(timings) / len(timings), 2) if timings else None,
                "timeout": "*" in rest and not timings,
                "raw": rest,
            }
        )
    return {
        "timestamp": utc_now(),
        "target": target,
        "ok": bool(hops) and not error,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
        "hops": hops,
        "error": error,
    }


def is_private_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0]).is_private
    except ValueError:
        return False


def vpn_leak_report(adapter: MacOSAdapter) -> Dict[str, Any]:
    vpn = adapter.vpn_status()
    resolvers = adapter.dns_resolvers()
    dns_routes = []
    findings: List[Finding] = []
    vpn_prefixes = ("utun", "tun", "tap", "ppp", "ipsec", "wg")
    servers = sorted({server for resolver in resolvers for server in resolver.get("nameservers", [])})
    for server in servers:
        try:
            route = adapter.route_for(server)
        except (CommandError, ValueError):
            route = {}
        interface = route.get("interface", "unknown")
        dns_routes.append({"server": server, "interface": interface, "route": route})
        if vpn.get("full_tunnel_likely") and interface != "unknown" and not interface.startswith(vpn_prefixes):
            severity = "warning" if is_private_address(server) else "critical"
            findings.append(
                Finding(
                    severity,
                    "dns-outside-vpn",
                    "DNS route may bypass the VPN",
                    f"Resolver {server} is reached through {interface}, not a detected tunnel interface.",
                    "Enable the VPN DNS option or block DNS on physical interfaces.",
                )
            )
    try:
        ipv6_routes = parse_routes(run_command(["/usr/sbin/netstat", "-rn", "-f", "inet6"]))
    except CommandError:
        ipv6_routes = []
    ipv6_defaults = [route for route in ipv6_routes if route.get("destination") in ("default", "::/0")]
    for route in ipv6_defaults:
        interface = route.get("interface", "")
        if vpn.get("full_tunnel_likely") and interface and not interface.startswith(vpn_prefixes):
            findings.append(
                Finding(
                    "warning",
                    "ipv6-outside-vpn",
                    "IPv6 default route may bypass the VPN",
                    f"IPv6 default route uses {interface}.",
                    "Route IPv6 through the tunnel or disable IPv6 while using the VPN.",
                )
            )
    if not vpn.get("active"):
        findings.append(Finding("info", "vpn-not-active", "No active VPN detected", "Traffic appears to use physical interfaces."))
    elif not findings:
        findings.append(Finding("ok", "no-obvious-leaks", "No obvious route-level leaks detected", "DNS and default-route checks did not find a bypass."))
    return {
        "timestamp": utc_now(),
        "vpn": vpn,
        "dns_routes": dns_routes,
        "ipv6_default_routes": ipv6_defaults,
        "findings": [item.to_dict() for item in findings],
        "limitations": [
            "This is a local route audit; it cannot prove the public egress IP without contacting an external service.",
            "Encrypted DNS inside applications may not use the system resolver list.",
            "Split-tunnel routes may be intentional.",
        ],
    }


def diagnose(adapter: MacOSAdapter, active: bool = False, host: str = "1.1.1.1", domain: str = "example.com") -> Dict[str, Any]:
    started = time.monotonic()
    connections = adapter.connections()
    interfaces = adapter.interfaces()
    routes = adapter.routes()
    resolvers = adapter.dns_resolvers()
    vpn = adapter.vpn_status()
    proxy = adapter.proxy_config()
    findings: List[Finding] = []
    active_interfaces = [item for item in interfaces if item.status == "active" or ("UP" in item.flags and item.ipv4)]
    if not active_interfaces:
        findings.append(Finding("critical", "no-active-interface", "No active IP interface", "WireScope found no active interface with an IPv4 address."))
    if not resolvers:
        findings.append(Finding("critical", "no-dns", "No DNS resolver detected", "macOS did not expose a usable resolver."))
    defaults = [route for route in routes if route.get("destination") == "default"]
    if len(defaults) > 1:
        findings.append(
            Finding(
                "info",
                "multiple-default-routes",
                "Multiple IPv4 default routes",
                ", ".join(f"{item['interface']}→{item['gateway']}" for item in defaults),
                "This is normal with many VPNs; verify priority if traffic uses the wrong path.",
            )
        )
    public_listeners = [item for item in connections if item.state == "LISTEN" and item.local.host in ("*", "0.0.0.0", "::")]
    if public_listeners:
        sample = ", ".join(f"{item.process}:{item.local.port}" for item in public_listeners[:8])
        findings.append(
            Finding(
                "warning",
                "public-listeners",
                f"{len(public_listeners)} services listen on all interfaces",
                sample,
                "Confirm that each service is expected and protected by the macOS firewall.",
            )
        )
    closed = sum(item.state == "CLOSED" for item in connections)
    if closed > 50:
        findings.append(Finding("info", "many-closed-sockets", "Many recently closed sockets", f"lsof reports {closed} CLOSED sockets; this may indicate high connection churn."))
    if vpn.get("active"):
        leak = vpn_leak_report(adapter)
        findings.extend(Finding(**item) for item in leak["findings"] if item["severity"] not in ("ok", "info"))
    if proxy:
        findings.append(Finding("info", "system-proxy", "System proxy configuration is active", json.dumps(proxy, ensure_ascii=False)))
    if not findings:
        findings.append(Finding("ok", "baseline-clean", "No obvious local configuration problems", "Interfaces, routes and DNS configuration look internally consistent."))
    active_report = quality_report(host, domain) if active else None
    if active_report:
        if active_report["score"] < 50:
            findings.append(Finding("critical", "quality-poor", "Poor active network quality", f"Active quality score: {active_report['score']}/100."))
        elif active_report["score"] < 75:
            findings.append(Finding("warning", "quality-degraded", "Degraded active network quality", f"Active quality score: {active_report['score']}/100."))
    weights = {"critical": 30, "warning": 12, "info": 0, "ok": 0}
    score = max(0, 100 - sum(weights.get(item.severity, 0) for item in findings))
    return {
        "timestamp": utc_now(),
        "score": score,
        "summary": {
            "connections": len(connections),
            "remote_connections": sum(item.remote is not None for item in connections),
            "interfaces": len(interfaces),
            "active_interfaces": [item.name for item in active_interfaces],
            "dns_servers": sorted({server for resolver in resolvers for server in resolver.get("nameservers", [])}),
            "vpn_active": bool(vpn.get("active")),
            "default_routes": defaults,
            "collection_ms": round((time.monotonic() - started) * 1000, 2),
        },
        "findings": [item.to_dict() for item in findings],
        "active_quality": active_report,
    }
