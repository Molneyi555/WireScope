from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import __version__
from .analyzer import analyze_recording, compare_recordings, export_har, export_requests_csv
from .capture import analyze_pcap, capture_packets, watch_dns
from .cdp import CDPError, launch_chrome, record_browser
from .config import default_user_path, get as config_get, load_config, write_default_config
from .diagnostics import diagnose, dns_compare, inspect_tls, trace_route, vpn_leak_report
from .har import load_har
from .macos import CommandError, MacOSAdapter
from .models import Connection, utc_now
from .proxy import serve_proxy
from .quality import quality_report
from .record import record_connections
from .report import generate_comparison_html, generate_html_report
from .tui import format_bytes, live


COMMAND_NAMES = (
    "live connections routes route interfaces neighbors dns dns-test dns-watch vpn leaks diagnose quality speed tls trace "
    "wifi bluetooth record snapshot capture pcap proxy browser web har analyze report compare export doctor config completion"
)


def json_print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def print_connections(connections: Iterable[Connection], limit: int) -> None:
    values = list(connections)
    print(f"{'PROCESS':16} {'PID':>7} {'PROTO':5} {'LOCAL':28} {'REMOTE':34} {'STATE':13} PATH")
    print("-" * 120)
    for item in values[:limit]:
        remote = item.remote.display() if item.remote else "—"
        print(
            f"{item.process[:16]:16} {item.pid:>7} {item.protocol:5} "
            f"{item.local.display()[:28]:28} {remote[:34]:34} {item.state[:13]:13} {item.path}"
        )
    if len(values) > limit:
        print(f"… {len(values) - limit} more; pass --limit to show more")


def print_nested(value: Any, prefix: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            print_nested(item, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            print_nested(item, f"{prefix}[{index}]")
    elif value not in (None, "", [], {}):
        print(f"{prefix}: {value}")


def command_connections(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    connections = adapter.connections()
    if args.process:
        connections = [item for item in connections if args.process.lower() in item.process.lower()]
    if args.remote_only:
        connections = [item for item in connections if item.remote is not None]
    if args.state:
        connections = [item for item in connections if item.state.lower() == args.state.lower()]
    if args.json:
        json_print({"timestamp": utc_now(), "count": len(connections), "connections": [item.to_dict() for item in connections]})
    else:
        print_connections(connections, args.limit)


def command_routes(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    routes = adapter.routes()
    if args.default:
        routes = [route for route in routes if route["destination"] == "default"]
    if args.json:
        json_print(routes)
        return
    print(f"{'DESTINATION':22} {'GATEWAY':28} {'INTERFACE':12} FLAGS")
    print("-" * 80)
    for route in routes[: args.limit]:
        print(f"{route['destination'][:22]:22} {route['gateway'][:28]:28} {route['interface']:12} {route['flags']}")
    if len(routes) > args.limit:
        print(f"… {len(routes) - args.limit} more")


def command_dns(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    result: Dict[str, Any] = {"resolvers": adapter.dns_resolvers()}
    if args.resolve:
        result["lookup"] = {"domain": args.resolve, "addresses": adapter.resolve(args.resolve)}
    if args.json:
        json_print(result)
    else:
        print("DNS resolvers")
        if not result["resolvers"]:
            print("  macOS did not expose a resolver configuration")
        for resolver in result["resolvers"]:
            print(f"  #{resolver.get('id', '?')}: {', '.join(resolver.get('nameservers', [])) or 'scoped/system resolver'}")
            if resolver.get("if_index"):
                print(f"      interface: {resolver['if_index']}")
            if resolver.get("search_domains"):
                print(f"      search: {', '.join(resolver['search_domains'])}")
        if args.resolve:
            print(f"\n{args.resolve}")
            for family, address in result["lookup"]["addresses"]:
                print(f"  {family}: {address}")


def command_vpn(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    status = adapter.vpn_status()
    if args.json:
        json_print(status)
        return
    print(f"VPN: {'ACTIVE' if status['active'] else 'NOT DETECTED'}")
    print(f"Full tunnel likely: {'yes' if status['full_tunnel_likely'] else 'no'}")
    for interface in status["interfaces"]:
        addresses = interface["ipv4"] + interface["ipv6"]
        print(f"  {interface['name']}: MTU {interface['mtu'] or '?'} · {', '.join(addresses) or 'no address'}")
    for route in status["default_routes"]:
        print(f"  default → {route['gateway']} via {route['interface']}")
    for warning in status["warnings"]:
        print(f"WARNING: {warning}")


def command_interfaces(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    interfaces = adapter.interfaces()
    counters = adapter.interface_counters()
    result = []
    for item in interfaces:
        value = item.to_dict()
        value["counters"] = counters.get(item.name, {})
        result.append(value)
    if args.json:
        json_print(result)
        return
    print(f"{'NAME':10} {'STATUS':10} {'MTU':>7} {'RX':>12} {'TX':>12} ADDRESSES")
    print("-" * 100)
    for item in result:
        status = item["status"] if item["status"] != "unknown" else ("up" if "UP" in item["flags"] else "down")
        addresses = ", ".join(item["ipv4"] + item["ipv6"])
        values = item["counters"]
        print(
            f"{item['name']:10} {status:10} {item['mtu'] or 0:>7} "
            f"{format_bytes(values.get('rx_bytes', 0)):>12} {format_bytes(values.get('tx_bytes', 0)):>12} {addresses}"
        )


def command_route(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    result = adapter.route_for(args.target)
    if args.json:
        json_print(result)
    elif not result:
        print("No route information returned")
    else:
        for key, value in result.items():
            print(f"{key.replace('_', ' ').title():14}: {value}")


def command_tls(args: argparse.Namespace) -> None:
    result = inspect_tls(args.domain, port=args.port, timeout=args.timeout)
    if args.json:
        json_print(result)
        return
    print(f"TLS {args.domain}:{args.port}: {'OK' if result['ok'] else 'FAILED'}")
    if not result["ok"]:
        print(f"  {result.get('error', 'unknown error')}")
        return
    timings = result["timing_ms"]
    print(f"  Peer:       {result['peer']['address']}:{result['peer']['port']}")
    print(f"  Protocol:   {result['tls_version']} · {result.get('alpn') or 'no ALPN'}")
    cipher = result.get("cipher") or {}
    print(f"  Cipher:     {cipher.get('name', '—')} ({cipher.get('bits', '—')} bit)")
    print(f"  Timing:     DNS {timings['dns']:.1f}ms · TCP {timings['tcp']:.1f}ms · TLS {timings['tls']:.1f}ms")
    certificate = result["certificate"]
    print(f"  Subject:    {certificate['subject'].get('commonName', '—')}")
    print(f"  Issuer:     {certificate['issuer'].get('commonName', '—')}")
    print(f"  Expires:    {certificate.get('not_after') or '—'} ({certificate.get('days_remaining')} days)")
    print(f"  SAN count:  {len(certificate.get('subject_alt_names', []))}")


def command_trace(args: argparse.Namespace) -> None:
    result = trace_route(args.target, max_hops=args.max_hops, wait=args.wait)
    if args.json:
        json_print(result)
        return
    print(f"Traceroute to {args.target} · {result['duration_ms']:.0f}ms")
    if result.get("error"):
        print(f"  {result['error']}")
    for hop in result["hops"]:
        address = ", ".join(hop["addresses"]) or "*"
        samples = "  ".join(f"{value:.1f}ms" for value in hop["samples_ms"]) or "timeout"
        print(f"{hop['hop']:>2}  {address:40} {samples}")


def command_dns_test(args: argparse.Namespace) -> None:
    servers = [item.strip() for item in args.servers.split(",") if item.strip()]
    report = dns_compare(args.domain, servers, query_type=args.type, timeout=args.timeout)
    if args.json:
        json_print(report)
        return
    print(f"DNS comparison for {args.domain} {args.type} · fastest: {report.get('fastest') or 'none'}")
    for item in report["results"]:
        state = item.get("rcode_name") if item.get("ok") else "FAIL"
        answers = [str(record["value"]) for record in item.get("records", []) if record["section"] == "answer"]
        print(f"  {item['server']:39} {state:10} {item['duration_ms']:>8.2f}ms  {', '.join(answers) or item.get('error', 'no answer')}")
    if report["answers_differ"]:
        print("  NOTE: resolvers returned different answer sets (often normal with CDNs).")


def command_leaks(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    report = vpn_leak_report(adapter)
    if args.json:
        json_print(report)
        return
    print("VPN / DNS route leak audit")
    for item in report["dns_routes"]:
        print(f"  DNS {item['server']:39} via {item['interface']}")
    for item in report["ipv6_default_routes"]:
        print(f"  IPv6 default via {item.get('interface')} → {item.get('gateway')}")
    print()
    for finding in report["findings"]:
        marker = {"critical": "!!", "warning": "!", "ok": "✓", "info": "i"}.get(finding["severity"], "-")
        print(f"{marker} {finding['title']}: {finding['detail']}")
        if finding.get("recommendation"):
            print(f"   {finding['recommendation']}")


def command_diagnose(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    report = diagnose(adapter, active=args.active, host=args.host, domain=args.domain)
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        json_print(report)
        return
    print(f"WireScope diagnosis score: {report['score']}/100")
    summary = report["summary"]
    print(
        f"Connections {summary['connections']} · Interfaces {', '.join(summary['active_interfaces']) or 'none'} · "
        f"VPN {'active' if summary['vpn_active'] else 'off'} · collection {summary['collection_ms']:.0f}ms"
    )
    for finding in report["findings"]:
        marker = {"critical": "CRITICAL", "warning": "WARNING", "ok": "OK", "info": "INFO"}.get(finding["severity"], finding["severity"].upper())
        print(f"\n[{marker}] {finding['title']}\n  {finding['detail']}")
        if finding.get("recommendation"):
            print(f"  Recommendation: {finding['recommendation']}")
    if args.output:
        print(f"\nReport written to {args.output}")


def command_speed(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    report = adapter.native_network_quality(interface=args.interface, max_runtime=args.max_runtime)
    if args.json:
        json_print(report)
    else:
        print_nested(report)


def command_dns_watch(args: argparse.Namespace) -> None:
    summary = watch_dns(args.interface, args.duration, output=args.output)
    print("\nDNS watch summary")
    print(f"  Queries:   {summary['queries']}")
    print(f"  Responses: {summary['responses']}")
    print(f"  Servers:   {', '.join(summary['servers']) or 'none observed'}")
    if args.output:
        print(f"  Events:    {args.output}")
    print(f"  {summary['note']}")


def command_pcap(args: argparse.Namespace) -> None:
    report = analyze_pcap(args.file, packet_limit=args.limit)
    if args.json:
        json_print(report)
        return
    print(f"PCAP {args.file}: {report['packets']} packets · {format_bytes(report['file_bytes'])} file · {format_bytes(report['payload_bytes_observed'])} observed payload")
    print(f"Protocols: {report['protocols']}")
    print("\nTop conversations")
    for conversation, count in list(report["top_conversations"].items())[:15]:
        print(f"  {count:>8}  {conversation}")
    print("\nTop ports: " + ", ".join(f"{port}({count})" for port, count in list(report["top_ports"].items())[:15]))


def command_neighbors(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    values = adapter.neighbors()
    if not args.all:
        filtered = []
        for item in values:
            try:
                from ipaddress import ip_address

                address = item["address"].split("%", 1)[0]
                if ip_address(address).is_multicast or item["mac"] == "(incomplete)":
                    continue
            except ValueError:
                pass
            filtered.append(item)
        values = filtered
    if args.json:
        json_print(values)
        return
    print(f"{'FAMILY':7} {'ADDRESS':42} {'MAC':20} {'IFACE':8} STATE")
    print("-" * 105)
    for item in values:
        print(f"{item['family']:7} {item['address'][:42]:42} {item['mac'][:20]:20} {item['interface']:8} {item['state']}")


def command_quality(args: argparse.Namespace) -> None:
    report = quality_report(args.host, args.domain, count=args.count, url=args.url)
    if args.json:
        json_print(report)
        return
    print(f"Network score: {report['score']}/100")
    for key in ("ping", "dns", "tls", "http"):
        probe = report[key]
        state = "OK" if probe["ok"] else "FAIL"
        duration = f"{probe['duration_ms']:.1f} ms" if probe.get("duration_ms") is not None else "—"
        print(f"  {key.upper():5} {state:4} {duration:>10}  {probe['target']}")
        if probe.get("error"):
            print(f"        {probe['error']}")
        elif args.verbose:
            print(f"        {json.dumps(probe['details'], ensure_ascii=False)}")


def command_har(args: argparse.Namespace) -> None:
    report = load_har(args.file, show_sensitive=args.show_sensitive)
    if args.json:
        json_print(report)
        return
    summary = report["summary"]
    print(
        f"Requests {summary['requests']} · Failed {summary['failed']} · Domains {summary['domains']} · "
        f"Transfer {format_bytes(summary['total_transfer_bytes'])}"
    )
    print(f"Protocols: {summary['protocols']}")
    print(f"Methods:   {summary['methods']}")
    print(f"{'METHOD':7} {'STATUS':6} {'TIME':9} {'SIZE':10} URL")
    print("-" * 110)
    for item in report["requests"][: args.limit]:
        print(
            f"{item['method'][:7]:7} {item['status']:>6} {item['duration_ms']:>7.1f}ms "
            f"{format_bytes(item['transfer_bytes']):>10} {item['url'][:70]}"
        )


def print_analysis(report: Dict[str, Any], limit: int = 25, sort: str = "slowest") -> None:
    summary = report.get("summary", {})
    print(f"WireScope analysis · {report.get('source_type', 'recording')}")
    if "requests" in summary:
        print(
            f"Requests {summary.get('requests', 0)} · Domains {summary.get('domains', 0)} · "
            f"Transfer {format_bytes(summary.get('transfer_bytes', 0))} · Span {summary.get('page_span_ms', 0):.1f}ms"
        )
        print(
            f"Errors {summary.get('failed', 0) + summary.get('http_errors', 0)} · Cache {summary.get('cache_percent', 0)}% · "
            f"Third-party {summary.get('third_party_percent', 0)}% · Trackers {summary.get('trackers', 0)}"
        )
    else:
        print(json.dumps(summary, ensure_ascii=False))
    scores = report.get("scores", {})
    if scores:
        print("Scores: " + " · ".join(f"{key} {value}/100" for key, value in scores.items()))
    print("\nFindings")
    for finding in report.get("findings", []):
        marker = {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO", "ok": "OK"}.get(finding.get("severity"), "INFO")
        print(f"  [{marker}] {finding.get('title')}")
        if finding.get("recommendation"):
            print(f"           {finding['recommendation']}")
    requests = list(report.get("requests", []))
    if not requests:
        return
    if sort == "largest":
        requests.sort(key=lambda item: item.get("transfer_bytes", 0) or 0, reverse=True)
    elif sort == "errors":
        requests.sort(key=lambda item: (not (item.get("failed") or (item.get("status", 0) or 0) >= 400), -(item.get("status", 0) or 0)))
    elif sort == "start":
        requests.sort(key=lambda item: item.get("offset_ms", 0) or 0)
    else:
        requests.sort(key=lambda item: item.get("duration_ms", 0) or 0, reverse=True)
    print(f"\nRequests · {sort}")
    print(f"{'METHOD':7} {'STATUS':>6} {'TIME':>10} {'SIZE':>10} {'TYPE':12} URL")
    print("-" * 120)
    for item in requests[:limit]:
        print(
            f"{str(item.get('method', '?'))[:7]:7} {int(item.get('status', 0) or 0):>6} "
            f"{(str(round(item.get('duration_ms', 0) or 0, 1)) + 'ms'):>10} {format_bytes(item.get('transfer_bytes', 0)):>10} "
            f"{str(item.get('resource_type', 'Other'))[:12]:12} {str(item.get('url', ''))[:70]}"
        )


def command_analyze(args: argparse.Namespace) -> None:
    report = analyze_recording(args.file, show_sensitive=args.show_sensitive)
    if args.json:
        json_print(report)
    else:
        print_analysis(report, limit=args.limit, sort=args.sort)


def default_report_path(source: str) -> str:
    path = Path(source)
    return str(path.with_name(path.stem + "-report.html"))


def command_report(args: argparse.Namespace) -> None:
    report = analyze_recording(args.file, show_sensitive=args.show_sensitive)
    output = args.output or default_report_path(args.file)
    generate_html_report(report, output, title=args.title)
    print(f"Interactive HTML report written to {output} ({format_bytes(Path(output).stat().st_size)})")


def command_compare(args: argparse.Namespace) -> None:
    comparison = compare_recordings(args.before, args.after)
    if args.output:
        if args.output.lower().endswith(".html"):
            generate_comparison_html(comparison, args.output)
        else:
            Path(args.output).write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Comparison written to {args.output}")
    if args.json:
        json_print(comparison)
        return
    print(f"WireScope comparison\n  before: {args.before}\n  after:  {args.after}")
    print(f"\n{'METRIC':24} {'BEFORE':>12} {'AFTER':>12} {'DELTA':>12} {'CHANGE':>10}")
    for key, value in comparison["deltas"].items():
        percent = f"{value['percent']:+.1f}%" if value["percent"] is not None else "—"
        print(f"{key.replace('_', ' '):24} {value['before']:>12} {value['after']:>12} {value['delta']:>+12} {percent:>10}")
    if comparison["score_deltas"]:
        print("\nScores")
        for key, value in comparison["score_deltas"].items():
            print(f"  {key:14} {value['before']:>3} → {value['after']:>3}  ({value['delta']:+})")


def command_export(args: argparse.Namespace) -> None:
    report = analyze_recording(args.file, show_sensitive=args.show_sensitive)
    output = args.output
    if not output:
        output = str(Path(args.file).with_name(Path(args.file).stem + "." + args.format))
    if args.format == "csv":
        export_requests_csv(report, output)
    elif args.format == "har":
        export_har(report, output)
    elif args.format == "html":
        generate_html_report(report, output)
    else:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Exported {args.format.upper()} to {output} ({format_bytes(Path(output).stat().st_size)})")


def command_web(args: argparse.Namespace) -> None:
    url = args.url if "://" in args.url else "https://" + args.url
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or "site"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", host).strip("-") or "site"
    if args.duration <= 0:
        raise ValueError("duration must be positive")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = Path(args.output_dir) / f"{slug}-{timestamp}"
    directory.mkdir(parents=True, exist_ok=True)
    jsonl_path = directory / "network.jsonl"
    report_path = directory / "report.html"
    analysis_path = directory / "analysis.json"
    csv_path = directory / "requests.csv"
    har_path = directory / "requests.har"
    print(f"Recording {url} for {args.duration:g}s…")
    chrome = launch_chrome(args.port, args.profile, "about:blank", headless=not args.show_browser)
    try:
        _target, summary = record_browser(
            "127.0.0.1",
            args.port,
            0,
            str(jsonl_path),
            args.duration,
            url,
            not args.use_cache,
            args.capture_bodies,
            args.max_body_bytes,
            args.show_sensitive,
            not args.quiet,
            args.idle,
        )
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=3)
        except subprocess.TimeoutExpired:
            chrome.kill()
    report = analyze_recording(str(jsonl_path), show_sensitive=args.show_sensitive)
    analysis_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    generate_html_report(report, str(report_path), title=f"WireScope · {url}")
    export_requests_csv(report, str(csv_path))
    export_har(report, str(har_path))
    print(
        f"\nDone · {summary['requests']} requests · score {report.get('scores', {}).get('overall', '—')}/100\n"
        f"  HTML:     {report_path}\n  Analysis: {analysis_path}\n  JSONL:    {jsonl_path}\n  CSV:      {csv_path}\n  HAR:      {har_path}"
    )
    if args.open_report:
        subprocess.run(["/usr/bin/open", str(report_path)], check=False)


def command_config(args: argparse.Namespace) -> None:
    config, loaded_path, error = load_config()
    if args.action == "path":
        print(loaded_path or default_user_path())
        return
    if args.action == "init":
        destination = Path.cwd() / ".wirescope.json" if args.local else default_user_path()
        write_default_config(destination, overwrite=args.force)
        print(f"WireScope configuration written to {destination}")
        return
    json_print({"path": str(loaded_path) if loaded_path else None, "error": error, "effective": config})


def command_completion(args: argparse.Namespace) -> None:
    commands = COMMAND_NAMES.split()
    if args.shell == "bash":
        print("# Add to ~/.bashrc: eval \"$(wirescope completion bash)\"")
        print(f"complete -W '{' '.join(commands)}' wirescope")
    elif args.shell == "fish":
        print("# Save as ~/.config/fish/completions/wirescope.fish")
        for command in commands:
            print(f"complete -c wirescope -f -a {command}")
    else:
        print("# Add to ~/.zshrc: eval \"$(wirescope completion zsh)\"")
        print("#compdef wirescope")
        print(f"_arguments '1:command:({' '.join(commands)})' '*::argument:->args'")


def command_snapshot(args: argparse.Namespace, adapter: MacOSAdapter) -> None:
    connections = adapter.connections()
    report = {
        "timestamp": utc_now(),
        "version": __version__,
        "connections": [item.to_dict() for item in connections],
        "connection_summary": {
            "total": len(connections),
            "remote": sum(item.remote is not None for item in connections),
            "by_process": dict(Counter(item.process for item in connections).most_common()),
            "by_protocol": dict(Counter(item.protocol for item in connections)),
        },
        "interfaces": [item.to_dict() for item in adapter.interfaces()],
        "routes": adapter.routes(),
        "dns": adapter.dns_resolvers(),
        "vpn": adapter.vpn_status(),
        "proxy": adapter.proxy_config(),
        "interface_counters": adapter.interface_counters(),
    }
    if args.radios:
        report["wifi"] = adapter.wifi_info()
        report["bluetooth"] = adapter.bluetooth_info()
    if args.quality:
        report["quality"] = quality_report(args.host, args.domain, count=args.count)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Snapshot written to {destination} ({format_bytes(destination.stat().st_size)})")


def command_doctor(args: argparse.Namespace) -> int:
    required_commands = (
        "/usr/sbin/lsof",
        "/usr/sbin/netstat",
        "/sbin/ifconfig",
        "/usr/sbin/scutil",
    )
    optional_commands = (
        ("/usr/sbin/tcpdump", "packet and DNS capture"),
        ("/usr/sbin/system_profiler", "Wi-Fi and Bluetooth inventory"),
        ("/usr/sbin/arp", "IPv4 neighbor table"),
        ("/usr/sbin/ndp", "IPv6 neighbor table"),
        ("/usr/sbin/traceroute", "route tracing"),
        ("/usr/bin/networkQuality", "capacity and responsiveness test"),
        ("/usr/bin/wdutil", "privileged deep Wi-Fi diagnostics"),
    )
    checks: List[Dict[str, Any]] = []
    checks.append({"name": "macOS", "ok": sys.platform == "darwin", "required": True, "detail": sys.platform})
    checks.append({"name": "Python >= 3.9", "ok": sys.version_info >= (3, 9), "required": True, "detail": sys.version.split()[0]})
    for command in required_commands:
        exists = Path(command).exists()
        checks.append({"name": command, "ok": exists, "required": True, "detail": "native sensor"})
    for command, purpose in optional_commands:
        exists = Path(command).exists()
        checks.append({"name": command, "ok": exists, "required": False, "detail": purpose})
    chrome_candidates = (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    )
    chrome = next((path for path in chrome_candidates if Path(path).exists()), None)
    checks.append({"name": "Chrome/Chromium", "ok": bool(chrome), "required": False, "detail": chrome or "needed only for browser/web commands"})
    config, config_path, config_error = load_config()
    checks.append({"name": "Configuration", "ok": config_error is None, "required": False, "detail": str(config_path or "defaults") if not config_error else config_error})
    checks.append({"name": "Packet-capture privilege", "ok": os.geteuid() == 0, "required": False, "detail": "root" if os.geteuid() == 0 else "run capture/dns-watch with sudo"})
    ok = all(item["ok"] for item in checks if item["required"])
    result = {"version": __version__, "ok": ok, "checks": checks}
    if args.json:
        json_print(result)
        return 0 if ok else 1
    print(f"WireScope {__version__} doctor")
    for item in checks:
        label = "OK" if item["ok"] else ("OPTIONAL" if not item["required"] else "MISSING")
        print(f"  {label:8} {item['name']:32} {item['detail']}")
    print(f"\n{'Ready.' if ok else 'Required capabilities are missing.'}")
    return 0 if ok else 1


def build_parser(config: Optional[Dict[str, Any]] = None) -> argparse.ArgumentParser:
    if config is None:
        config, _path, _error = load_config()
    parser = argparse.ArgumentParser(
        prog="wirescope",
        description="Privacy-first terminal network observability",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Quick start:
  wirescope                         open the interactive dashboard
  wirescope web https://example.com record and analyze a website
  wirescope diagnose                audit local network configuration
  wirescope quality --verbose       test latency, DNS, TLS and HTTP
  wirescope --help                  list every specialized command

Data stays local and sensitive fields are redacted by default.""",
    )
    parser.add_argument("--version", action="version", version=f"WireScope {__version__}")
    sub = parser.add_subparsers(dest="command")

    connections = sub.add_parser("connections", aliases=["conns"], help="list TCP/UDP sockets with owning processes")
    connections.add_argument("--process", help="case-insensitive process filter")
    connections.add_argument("--state", help="socket state filter, e.g. ESTABLISHED")
    connections.add_argument("--remote-only", action="store_true")
    connections.add_argument("--limit", type=int, default=100)
    connections.add_argument("--json", action="store_true")

    live_parser = sub.add_parser("live", help="continuously refreshed terminal dashboard")
    live_parser.add_argument("--interval", type=float, default=config_get(config, "live", "interval", 1.5))
    live_parser.add_argument("--process")
    live_parser.add_argument("--plain", action="store_true", help="print one non-interactive snapshot")

    routes = sub.add_parser("routes", help="show IPv4 routing table")
    routes.add_argument("--default", action="store_true")
    routes.add_argument("--limit", type=int, default=200)
    routes.add_argument("--json", action="store_true")

    dns = sub.add_parser("dns", help="show resolvers and resolve a domain")
    dns.add_argument("--resolve", metavar="DOMAIN")
    dns.add_argument("--json", action="store_true")

    vpn = sub.add_parser("vpn", help="inspect VPN interfaces and default routes")
    vpn.add_argument("--json", action="store_true")

    interfaces = sub.add_parser("interfaces", aliases=["ifaces"], help="show interfaces, addresses and traffic counters")
    interfaces.add_argument("--json", action="store_true")

    neighbors = sub.add_parser("neighbors", help="show known local ARP/NDP neighbors without scanning")
    neighbors.add_argument("--all", action="store_true", help="include multicast and incomplete entries")
    neighbors.add_argument("--json", action="store_true")

    route = sub.add_parser("route", help="show the effective route for a destination")
    route.add_argument("target")
    route.add_argument("--json", action="store_true")

    tls = sub.add_parser("tls", help="inspect TLS handshake, cipher and certificate")
    tls.add_argument("domain")
    tls.add_argument("--port", type=int, default=443)
    tls.add_argument("--timeout", type=float, default=5.0)
    tls.add_argument("--json", action="store_true")

    trace = sub.add_parser("trace", help="run and parse traceroute")
    trace.add_argument("target")
    trace.add_argument("--max-hops", type=int, default=20)
    trace.add_argument("--wait", type=float, default=1.0)
    trace.add_argument("--json", action="store_true")

    dns_test = sub.add_parser("dns-test", help="compare direct DNS responses and latency")
    dns_test.add_argument("domain")
    dns_test.add_argument("--servers", default=config_get(config, "dns", "comparison_servers", "1.1.1.1,8.8.8.8,9.9.9.9"))
    dns_test.add_argument("--type", choices=("A", "AAAA", "CNAME", "MX", "TXT", "HTTPS"), default="A")
    dns_test.add_argument("--timeout", type=float, default=2.0)
    dns_test.add_argument("--json", action="store_true")

    dns_watch = sub.add_parser("dns-watch", help="watch plaintext DNS packets live (usually needs sudo)")
    dns_watch.add_argument("--interface", "-i", default="any")
    dns_watch.add_argument("--duration", type=float, default=30.0)
    dns_watch.add_argument("--output", "-o", help="optional JSONL event recording")

    leaks = sub.add_parser("leaks", help="audit VPN, DNS and IPv6 routes for likely leaks")
    leaks.add_argument("--json", action="store_true")

    diagnose_parser = sub.add_parser("diagnose", help="run automatic local network diagnostics")
    diagnose_parser.add_argument("--active", action="store_true", help="also run external ping/DNS/TLS/HTTP probes")
    diagnose_parser.add_argument("--host", default="1.1.1.1")
    diagnose_parser.add_argument("--domain", default="example.com")
    diagnose_parser.add_argument("--output", "-o")
    diagnose_parser.add_argument("--json", action="store_true")

    speed = sub.add_parser("speed", help="run Apple's native networkQuality capacity/responsiveness test")
    speed.add_argument("--interface")
    speed.add_argument("--max-runtime", type=int, default=20)
    speed.add_argument("--json", action="store_true")

    wifi = sub.add_parser("wifi", help="show macOS Wi-Fi profiler data")
    wifi.add_argument("--json", action="store_true")
    wifi.add_argument("--deep", action="store_true", help="include privileged wdutil radio diagnostics when run with sudo")

    bluetooth = sub.add_parser("bluetooth", aliases=["bt"], help="show macOS Bluetooth profiler data")
    bluetooth.add_argument("--json", action="store_true")

    quality = sub.add_parser("quality", help="run ping, DNS, TLS and HTTP probes")
    quality.add_argument("--host", default=config_get(config, "quality", "host", "1.1.1.1"), help="ping target")
    quality.add_argument("--domain", default=config_get(config, "quality", "domain", "example.com"), help="DNS and TLS target")
    quality.add_argument("--url", help="HTTP HEAD target; defaults to https://DOMAIN/")
    quality.add_argument("--count", type=int, default=config_get(config, "quality", "count", 5))
    quality.add_argument("--verbose", action="store_true")
    quality.add_argument("--json", action="store_true")

    record = sub.add_parser("record", help="record connection open/close events to JSONL")
    record.add_argument("--duration", type=float, default=30.0)
    record.add_argument("--interval", type=float, default=1.0)
    record.add_argument("--process")
    record.add_argument("--output", "-o", default="wirescope-session.jsonl")

    snapshot = sub.add_parser("snapshot", help="export a comprehensive system network snapshot")
    snapshot.add_argument("--output", "-o", default="wirescope-snapshot.json")
    snapshot.add_argument("--radios", action="store_true", help="include Wi-Fi and Bluetooth profiler data")
    snapshot.add_argument("--quality", action="store_true", help="include active external quality probes")
    snapshot.add_argument("--host", default=config_get(config, "quality", "host", "1.1.1.1"))
    snapshot.add_argument("--domain", default=config_get(config, "quality", "domain", "example.com"))
    snapshot.add_argument("--count", type=int, default=config_get(config, "quality", "count", 5))

    proxy = sub.add_parser("proxy", help="run an HTTP forward proxy and HTTPS CONNECT observer")
    proxy.add_argument("--host", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=8080)
    proxy.add_argument("--output", "-o", help="append proxy events to JSONL")
    proxy.add_argument("--show-sensitive", action="store_true", help="record sensitive URL parameters and headers")
    proxy.add_argument("--capture-http-bodies", action="store_true", help="capture plaintext HTTP bodies; requires --show-sensitive")
    proxy.add_argument("--max-body-bytes", type=int, default=1_000_000)
    proxy.add_argument("--allow-remote", action="store_true", help="allow binding beyond loopback")

    har = sub.add_parser("har", help="analyze a browser HAR file")
    har.add_argument("file")
    har.add_argument("--limit", type=int, default=50)
    har.add_argument("--show-sensitive", action="store_true")
    har.add_argument("--json", action="store_true")

    analyze = sub.add_parser("analyze", help="deeply analyze CDP, proxy, connection JSONL or HAR")
    analyze.add_argument("file")
    analyze.add_argument("--sort", choices=("slowest", "largest", "errors", "start"), default="slowest")
    analyze.add_argument("--limit", type=int, default=25)
    analyze.add_argument("--show-sensitive", action="store_true")
    analyze.add_argument("--json", action="store_true")

    report_parser = sub.add_parser("report", help="create a self-contained interactive HTML report")
    report_parser.add_argument("file")
    report_parser.add_argument("--output", "-o")
    report_parser.add_argument("--title", default="WireScope Network Report")
    report_parser.add_argument("--show-sensitive", action="store_true")

    compare = sub.add_parser("compare", help="compare two recordings or HAR files")
    compare.add_argument("before")
    compare.add_argument("after")
    compare.add_argument("--output", "-o", help="optional .json or .html comparison")
    compare.add_argument("--json", action="store_true")

    export = sub.add_parser("export", help="export normalized requests to JSON, CSV or HTML")
    export.add_argument("file")
    export.add_argument("--format", choices=("json", "csv", "html", "har"), required=True)
    export.add_argument("--output", "-o")
    export.add_argument("--show-sensitive", action="store_true")

    browser = sub.add_parser("browser", help="record every Chrome DevTools network event")
    browser.add_argument("--host", default="127.0.0.1")
    browser.add_argument("--port", type=int, default=config_get(config, "browser", "port", 9223))
    browser.add_argument("--target", type=int, default=0, help="page target index")
    browser.add_argument("--launch", action="store_true", help="launch an isolated Chrome profile with DevTools enabled")
    browser.add_argument("--profile", default=config_get(config, "browser", "profile", "/private/tmp/wirescope-browser-profile"), help="profile used with --launch")
    browser.add_argument("--headless", action="store_true", help="use headless Chrome with --launch")
    browser.add_argument("--keep-browser", action="store_true", help="do not stop Chrome after a --launch recording")
    browser.add_argument("--duration", type=float, default=config_get(config, "browser", "duration", 20.0))
    browser.add_argument("--idle", type=float, default=config_get(config, "browser", "idle", 3.0), help="stop early after this many idle seconds once the page loads")
    browser.add_argument("--navigate", metavar="URL", help="navigate the selected tab before recording")
    browser_cache = browser.add_mutually_exclusive_group()
    browser_cache.add_argument("--disable-cache", dest="disable_cache", action="store_true")
    browser_cache.add_argument("--use-cache", dest="disable_cache", action="store_false")
    browser.set_defaults(disable_cache=bool(config_get(config, "browser", "disable_cache", True)))
    browser.add_argument("--capture-bodies", action="store_true", help="request response bodies from Chrome")
    browser.add_argument("--max-body-bytes", type=int, default=config_get(config, "browser", "max_body_bytes", 1_000_000))
    browser.add_argument("--show-sensitive", action="store_true")
    browser.add_argument("--quiet", action="store_true", help="do not print live request/response lines")
    browser.add_argument("--output", "-o", default="wirescope-browser.jsonl")
    browser.add_argument("--report", nargs="?", const="auto", help="also create an HTML report; optionally provide its path")

    web = sub.add_parser("web", help="one-command website recording, analysis and report bundle")
    web.add_argument("url")
    web.add_argument("--duration", type=float, default=config_get(config, "browser", "duration", 20.0))
    web.add_argument("--idle", type=float, default=config_get(config, "browser", "idle", 3.0), help="stop after network idle; duration remains the maximum")
    web.add_argument("--output-dir", default=config_get(config, "output", "directory", "wirescope-results"))
    web.add_argument("--port", type=int, default=config_get(config, "browser", "port", 9223))
    web.add_argument("--profile", default=config_get(config, "browser", "profile", "/private/tmp/wirescope-browser-profile"))
    web.add_argument("--show-browser", action="store_true", help="show Chrome instead of using headless mode")
    web.add_argument("--use-cache", action="store_true", help="do not disable the browser cache")
    web.add_argument("--capture-bodies", action="store_true")
    web.add_argument("--max-body-bytes", type=int, default=config_get(config, "browser", "max_body_bytes", 1_000_000))
    web.add_argument("--show-sensitive", action="store_true")
    web.add_argument("--quiet", action="store_true")
    web.add_argument("--open-report", action="store_true", help="open the generated report in the default browser")

    capture = sub.add_parser("capture", help="write local packets to PCAP using tcpdump (usually needs sudo)")
    capture.add_argument("--interface", "-i", default="any")
    capture.add_argument("--duration", type=float, default=30.0)
    capture.add_argument("--output", "-o", default="wirescope.pcap")
    capture.add_argument("expression", nargs=argparse.REMAINDER, help="optional tcpdump filter, e.g. port 53")

    pcap = sub.add_parser("pcap", help="summarize a PCAP/PCAPNG using native tcpdump")
    pcap.add_argument("file")
    pcap.add_argument("--limit", type=int, default=0, help="stop after N packets; 0 reads all")
    pcap.add_argument("--json", action="store_true")

    doctor = sub.add_parser("doctor", help="check local runtime capabilities")
    doctor.add_argument("--json", action="store_true")

    config_parser = sub.add_parser("config", help="show or initialize WireScope configuration")
    config_parser.add_argument("action", choices=("show", "path", "init"), nargs="?", default="show")
    config_parser.add_argument("--local", action="store_true", help="write .wirescope.json in the current directory")
    config_parser.add_argument("--force", action="store_true")

    completion = sub.add_parser("completion", help="generate shell completion for zsh, bash or fish")
    completion.add_argument("shell", choices=("zsh", "bash", "fish"))
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    config, _config_path, config_error = load_config()
    parser = build_parser(config)
    args = parser.parse_args(argv)
    if config_error:
        print(f"wirescope: ignoring invalid config: {config_error}", file=sys.stderr)
    adapter = MacOSAdapter()
    try:
        if args.command is None:
            live(adapter, float(config_get(config, "live", "interval", 1.5)))
        elif args.command in ("connections", "conns"):
            command_connections(args, adapter)
        elif args.command == "live":
            live(adapter, max(0.25, args.interval), process=args.process, plain=args.plain)
        elif args.command == "routes":
            command_routes(args, adapter)
        elif args.command == "dns":
            command_dns(args, adapter)
        elif args.command == "vpn":
            command_vpn(args, adapter)
        elif args.command in ("interfaces", "ifaces"):
            command_interfaces(args, adapter)
        elif args.command == "neighbors":
            command_neighbors(args, adapter)
        elif args.command == "route":
            command_route(args, adapter)
        elif args.command == "tls":
            command_tls(args)
        elif args.command == "trace":
            command_trace(args)
        elif args.command == "dns-test":
            command_dns_test(args)
        elif args.command == "dns-watch":
            command_dns_watch(args)
        elif args.command == "leaks":
            command_leaks(args, adapter)
        elif args.command == "diagnose":
            command_diagnose(args, adapter)
        elif args.command == "speed":
            command_speed(args, adapter)
        elif args.command == "wifi":
            value = adapter.wifi_info(deep=args.deep)
            json_print(value) if args.json else print_nested(value)
        elif args.command in ("bluetooth", "bt"):
            value = adapter.bluetooth_info()
            json_print(value) if args.json else print_nested(value)
        elif args.command == "quality":
            command_quality(args)
        elif args.command == "record":
            if args.duration <= 0 or args.interval <= 0:
                parser.error("record duration and interval must be positive")
            summary = record_connections(adapter, args.output, args.duration, args.interval, process=args.process)
            print(f"Recorded {summary['snapshots']} snapshots: {summary['opened']} opened, {summary['closed']} closed → {args.output}")
        elif args.command == "snapshot":
            command_snapshot(args, adapter)
        elif args.command == "proxy":
            asyncio.run(
                serve_proxy(
                    args.host,
                    args.port,
                    args.output,
                    args.show_sensitive,
                    args.allow_remote,
                    args.capture_http_bodies,
                    args.max_body_bytes,
                )
            )
        elif args.command == "har":
            command_har(args)
        elif args.command == "analyze":
            command_analyze(args)
        elif args.command == "report":
            command_report(args)
        elif args.command == "compare":
            command_compare(args)
        elif args.command == "export":
            command_export(args)
        elif args.command == "browser":
            chrome_process = None
            if args.launch:
                chrome_process = launch_chrome(args.port, args.profile, "about:blank", args.headless)
                print(f"Chrome DevTools ready on 127.0.0.1:{args.port} (PID {chrome_process.pid})")
            try:
                target, summary = record_browser(
                    args.host,
                    args.port,
                    args.target,
                    args.output,
                    args.duration,
                    args.navigate,
                    args.disable_cache,
                    args.capture_bodies,
                    args.max_body_bytes,
                    args.show_sensitive,
                    not args.quiet,
                    args.idle,
                )
            finally:
                if chrome_process is not None and not args.keep_browser:
                    chrome_process.terminate()
            source = args.navigate or target.get("url") or target.get("title") or "Chrome target"
            print(f"Recorded {summary['requests']} requests from {source!r} → {args.output}")
            json_print(summary)
            if args.report:
                report_path = default_report_path(args.output) if args.report == "auto" else args.report
                analyzed = analyze_recording(args.output, show_sensitive=args.show_sensitive)
                generate_html_report(analyzed, report_path, title=f"WireScope · {source}")
                print(f"HTML report → {report_path}")
        elif args.command == "web":
            command_web(args)
        elif args.command == "capture":
            code = capture_packets(args.interface, args.output, args.duration, args.expression or None)
            if code:
                raise SystemExit(code)
            print(f"Packet capture written to {args.output}")
        elif args.command == "pcap":
            command_pcap(args)
        elif args.command == "doctor":
            raise SystemExit(command_doctor(args))
        elif args.command == "config":
            command_config(args)
        elif args.command == "completion":
            command_completion(args)
    except (CommandError, CDPError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"wirescope: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
