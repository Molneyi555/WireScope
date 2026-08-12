from __future__ import annotations

import json
import re
import select
import signal
import subprocess
import time
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Dict, List, Optional

from .artifacts import external_artifact, private_text_stream
from .models import utc_now


SAFE_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]+$")
ENDPOINT = re.compile(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\.(?P<port>\d+)")


def validate_interface(interface: str) -> None:
    if not SAFE_INTERFACE.fullmatch(interface):
        raise ValueError("invalid interface name")


def capture_packets(interface: str, output: str, duration: float, expression: Optional[List[str]] = None) -> int:
    validate_interface(interface)
    with external_artifact(output) as path:
        command = ["/usr/sbin/tcpdump", "-n", "-i", interface, "-G", str(max(1, int(duration))), "-W", "1", "-w", str(path)]
        if expression:
            command.extend(expression)
        completed = subprocess.run(command, check=False)
    return completed.returncode


def parse_dns_tcpdump_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or " > " not in line or ".53:" not in line:
        return None
    endpoints = ENDPOINT.findall(line)
    source = destination = None
    endpoint_matches = list(ENDPOINT.finditer(line))
    if len(endpoint_matches) >= 2:
        source = {"host": endpoint_matches[0].group("host"), "port": int(endpoint_matches[0].group("port"))}
        destination = {"host": endpoint_matches[1].group("host"), "port": int(endpoint_matches[1].group("port"))}
    query = re.search(r"\b(\d+)\+?\s+\[?\d*[a-zA-Z]*\]?\s*(A|AAAA|HTTPS|CNAME|MX|TXT|PTR)\?\s+([^\s]+)", line)
    response = re.search(r"\b(\d+)\s+(?:NXDomain|ServFail|\d+/\d+/\d+)", line, re.IGNORECASE)
    event: Dict[str, Any] = {
        "type": "dns_packet",
        "timestamp": utc_now(),
        "source": source,
        "destination": destination,
        "raw": line,
    }
    if query:
        event.update(
            {
                "direction": "query",
                "transaction_id": int(query.group(1)),
                "query_type": query.group(2),
                "domain": query.group(3).rstrip("."),
            }
        )
    elif response:
        event.update({"direction": "response", "transaction_id": int(response.group(1))})
    else:
        event["direction"] = "unknown"
    return event


def watch_dns(interface: str, duration: float, output: Optional[str] = None) -> Dict[str, Any]:
    validate_interface(interface)
    command = ["/usr/sbin/tcpdump", "-l", "-n", "-tttt", "-i", interface, "port", "53"]
    with ExitStack() as stack:
        stream = stack.enter_context(private_text_stream(output)) if output else None
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,
        )
        started = time.monotonic()
        queries = 0
        responses = 0
        domains: Counter[str] = Counter()
        servers: Counter[str] = Counter()
        try:
            while time.monotonic() - started < duration and process.poll() is None:
                if process.stdout is None:
                    break
                readable, _writable, _errors = select.select([process.stdout], [], [], 0.25)
                if not readable:
                    continue
                line = process.stdout.readline()
                if not line:
                    continue
                event = parse_dns_tcpdump_line(line)
                if event is None:
                    continue
                if event["direction"] == "query":
                    queries += 1
                    domains[event.get("domain", "unknown")] += 1
                    destination = event.get("destination") or {}
                    if destination.get("host"):
                        servers[destination["host"]] += 1
                    print(f"→ {event.get('query_type', '?'):5} {event.get('domain', '?')}  dns={destination.get('host', '?')}", flush=True)
                elif event["direction"] == "response":
                    responses += 1
                if stream:
                    stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                    stream.flush()
        finally:
            if process.poll() is None:
                try:
                    process.send_signal(signal.SIGINT)
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate()
    stderr = process.stderr.read().strip() if process.stderr else ""
    if process.returncode not in (0, -signal.SIGINT, None) and queries == 0:
        raise RuntimeError(stderr or f"tcpdump exited with {process.returncode}; try running with sudo")
    return {
        "duration_seconds": round(time.monotonic() - started, 2),
        "queries": queries,
        "responses": responses,
        "top_domains": dict(domains.most_common(25)),
        "servers": dict(servers.most_common()),
        "output": output,
        "note": "Only plaintext DNS on port 53 is visible; DoH/DoT remains encrypted.",
    }


def parse_packet_line(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if not stripped:
        return None
    protocol = "other"
    if " Flags [" in stripped:
        protocol = "tcp"
    elif re.search(r"\bUDP, length\s+\d+", stripped):
        protocol = "udp"
    elif "ICMP" in stripped:
        protocol = "icmp"
    elif "ARP," in stripped:
        protocol = "arp"
    elif " IP6 " in f" {stripped} ":
        protocol = "ipv6"
    elif " IP " in f" {stripped} ":
        protocol = "ipv4"
    endpoint_matches = list(ENDPOINT.finditer(stripped))
    source = destination = None
    if len(endpoint_matches) >= 2:
        source = f"{endpoint_matches[0].group('host')}:{endpoint_matches[0].group('port')}"
        destination = f"{endpoint_matches[1].group('host')}:{endpoint_matches[1].group('port')}"
    length_match = re.search(r"\blength\s+(\d+)", stripped)
    return {
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "length": int(length_match.group(1)) if length_match else 0,
        "raw": stripped,
    }


def analyze_pcap(path: str, packet_limit: int = 0) -> Dict[str, Any]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(path)
    command = ["/usr/sbin/tcpdump", "-nn", "-tttt", "-r", str(source)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    protocols: Counter[str] = Counter()
    endpoints: Counter[str] = Counter()
    conversations: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    total_bytes = 0
    packets = 0
    samples: List[str] = []
    if process.stdout:
        for line in process.stdout:
            packet = parse_packet_line(line)
            if packet is None:
                continue
            packets += 1
            protocols[packet["protocol"]] += 1
            total_bytes += packet["length"]
            if packet["source"]:
                endpoints[packet["source"].rsplit(":", 1)[0]] += 1
                ports[packet["source"].rsplit(":", 1)[1]] += 1
            if packet["destination"]:
                endpoints[packet["destination"].rsplit(":", 1)[0]] += 1
                ports[packet["destination"].rsplit(":", 1)[1]] += 1
            if packet["source"] and packet["destination"]:
                pair = " ↔ ".join(sorted((packet["source"], packet["destination"])))
                conversations[pair] += 1
            if len(samples) < 50:
                samples.append(packet["raw"])
            if packet_limit and packets >= packet_limit:
                process.terminate()
                break
    process.wait()
    stderr = process.stderr.read().strip() if process.stderr else ""
    if process.returncode not in (0, -signal.SIGTERM) and packets == 0:
        raise RuntimeError(stderr or f"tcpdump exited with {process.returncode}")
    return {
        "timestamp": utc_now(),
        "source": str(source),
        "file_bytes": source.stat().st_size,
        "packets": packets,
        "payload_bytes_observed": total_bytes,
        "protocols": dict(protocols.most_common()),
        "top_endpoints": dict(endpoints.most_common(30)),
        "top_conversations": dict(conversations.most_common(30)),
        "top_ports": dict(ports.most_common(30)),
        "samples": samples,
        "stderr": stderr,
        "limited": bool(packet_limit and packets >= packet_limit),
    }
