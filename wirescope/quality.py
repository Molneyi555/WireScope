from __future__ import annotations

import re
import socket
import ssl
import statistics
import time
import urllib.request
from typing import Any, Dict, List, Optional

from .macos import CommandError, run_command
from .models import ProbeResult, utc_now
from .redact import safe_error


def ping_probe(host: str, count: int = 5) -> ProbeResult:
    started = time.monotonic()
    try:
        output = run_command(["/sbin/ping", "-n", "-c", str(count), "-W", "1000", host], timeout=max(5, count * 2))
    except CommandError as exc:
        return ProbeResult(target=host, ok=False, duration_ms=(time.monotonic() - started) * 1000, error=safe_error(str(exc)))
    loss_match = re.search(r"([\d.]+)% packet loss", output)
    stats_match = re.search(r"(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output)
    details: Dict[str, Any] = {"packet_loss_percent": float(loss_match.group(1)) if loss_match else None}
    if stats_match:
        details.update(
            {
                "min_ms": float(stats_match.group(1)),
                "avg_ms": float(stats_match.group(2)),
                "max_ms": float(stats_match.group(3)),
                "jitter_ms": float(stats_match.group(4)),
            }
        )
    return ProbeResult(
        target=host,
        ok=details.get("packet_loss_percent") != 100.0,
        duration_ms=(time.monotonic() - started) * 1000,
        details=details,
    )


def dns_probe(domain: str, attempts: int = 3) -> ProbeResult:
    timings: List[float] = []
    addresses = set()
    try:
        for _ in range(attempts):
            started = time.monotonic()
            results = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
            timings.append((time.monotonic() - started) * 1000)
            addresses.update(result[4][0] for result in results)
    except OSError as exc:
        return ProbeResult(target=domain, ok=False, error=safe_error(str(exc)), details={"samples_ms": timings})
    return ProbeResult(
        target=domain,
        ok=True,
        duration_ms=statistics.mean(timings),
        details={
            "samples_ms": [round(value, 2) for value in timings],
            "min_ms": round(min(timings), 2),
            "avg_ms": round(statistics.mean(timings), 2),
            "max_ms": round(max(timings), 2),
            "addresses": sorted(addresses),
        },
    )


def tls_probe(domain: str, port: int = 443, timeout: float = 5.0) -> ProbeResult:
    started = time.monotonic()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as raw:
            connected = time.monotonic()
            with context.wrap_socket(raw, server_hostname=domain) as secured:
                finished = time.monotonic()
                cipher = secured.cipher()
                certificate = secured.getpeercert()
                details = {
                    "tcp_ms": round((connected - started) * 1000, 2),
                    "tls_ms": round((finished - connected) * 1000, 2),
                    "version": secured.version(),
                    "cipher": cipher[0] if cipher else None,
                    "expires": certificate.get("notAfter"),
                    "alpn": secured.selected_alpn_protocol(),
                }
    except OSError as exc:
        return ProbeResult(target=f"{domain}:{port}", ok=False, duration_ms=(time.monotonic() - started) * 1000, error=safe_error(str(exc)))
    return ProbeResult(target=f"{domain}:{port}", ok=True, duration_ms=(finished - started) * 1000, details=details)


def http_probe(url: str, timeout: float = 10.0) -> ProbeResult:
    started = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "WireScope/0.2"}, method="HEAD")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            first_byte = time.monotonic()
            details = {
                "status": response.status,
                "ttfb_ms": round((first_byte - started) * 1000, 2),
                "server": response.headers.get("server"),
                "content_type": response.headers.get("content-type"),
                "http_version": f"HTTP/{response.version / 10:.1f}",
            }
    except Exception as exc:  # urllib exposes several transport-specific exception types
        return ProbeResult(target=url, ok=False, duration_ms=(time.monotonic() - started) * 1000, error=safe_error(str(exc)))
    return ProbeResult(target=url, ok=True, duration_ms=(time.monotonic() - started) * 1000, details=details)


def calculate_score(ping: ProbeResult, dns: ProbeResult, tls: ProbeResult, http: ProbeResult) -> int:
    score = 100.0
    if not ping.ok:
        score -= 45
    else:
        loss = ping.details.get("packet_loss_percent") or 0
        latency = ping.details.get("avg_ms") or 0
        jitter = ping.details.get("jitter_ms") or 0
        score -= min(35, loss * 2.5)
        score -= max(0, min(20, (latency - 30) / 10))
        score -= max(0, min(10, (jitter - 5) / 4))
    if not dns.ok:
        score -= 20
    elif (dns.duration_ms or 0) > 150:
        score -= 10
    elif (dns.duration_ms or 0) > 60:
        score -= 4
    if not tls.ok:
        score -= 15
    if not http.ok:
        score -= 15
    return max(0, min(100, round(score)))


def quality_report(host: str, domain: str, count: int = 5, url: Optional[str] = None) -> Dict[str, Any]:
    url = url or f"https://{domain}/"
    ping = ping_probe(host, count=count)
    dns = dns_probe(domain)
    tls = tls_probe(domain)
    http = http_probe(url)
    return {
        "timestamp": utc_now(),
        "score": calculate_score(ping, dns, tls, http),
        "ping": ping.to_dict(),
        "dns": dns.to_dict(),
        "tls": tls.to_dict(),
        "http": http.to_dict(),
    }
