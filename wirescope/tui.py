from __future__ import annotations

import curses
import copy
import hashlib
import json
import os
import shutil
import socket
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from . import __version__
from .artifacts import atomic_write_text
from .macos import MacOSAdapter
from .models import Connection, Interface, utc_now


TABS = ("Overview", "Connections", "Processes", "Interfaces", "DNS", "VPN", "Routes", "Timeline")
SPARKS = "▁▂▃▄▅▆▇█"


def fit(value: str, width: int) -> str:
    if width <= 0:
        return ""
    if width == 1:
        return value[:1]
    return value if len(value) <= width else value[: width - 1] + "…"


def format_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.1f}{unit}" if unit != "B" else f"{int(amount)}B"
        amount /= 1024
    return f"{value}B"


def format_rate(value: float) -> str:
    return f"{format_bytes(value)}/s"


def sparkline(values: Iterable[float], width: int = 24) -> str:
    items = list(values)[-width:]
    if not items:
        return "—"
    peak = max(items)
    if peak <= 0:
        return SPARKS[0] * len(items)
    return "".join(SPARKS[min(len(SPARKS) - 1, int((value / peak) * (len(SPARKS) - 1)))] for value in items)


def connection_target(connection: Connection) -> str:
    return connection.remote.display() if connection.remote else connection.local.display()


def event_time_label(timestamp: str) -> str:
    if "T" in timestamp and len(timestamp) >= 19:
        return timestamp[11:19]
    return fit(timestamp, 12)


def stable_fingerprint(value: Any) -> str:
    """Return a deterministic fingerprint for JSON-like sensor state."""

    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8", errors="replace")).hexdigest()


def network_state_summary(name: str, value: Any) -> str:
    """Build a compact, non-interpretive description of a native sensor snapshot."""

    if name == "routes":
        routes = value if isinstance(value, list) else []
        defaults = [item for item in routes if isinstance(item, dict) and item.get("destination") == "default"]
        if defaults:
            route = defaults[0]
            return f"{len(routes)} routes; default via {route.get('interface', '?')} → {route.get('gateway', '?')}"
        return f"{len(routes)} routes; no IPv4 default observed"
    if name == "dns":
        resolvers = value if isinstance(value, list) else []
        servers = {
            str(server)
            for resolver in resolvers
            if isinstance(resolver, dict)
            for server in resolver.get("nameservers", [])
        }
        return f"{len(resolvers)} resolvers; {', '.join(sorted(servers)) if servers else 'no nameservers exposed'}"
    if name == "vpn":
        vpn = value if isinstance(value, dict) else {}
        interfaces = [
            str(item.get("name"))
            for item in vpn.get("interfaces", [])
            if isinstance(item, dict) and item.get("name")
        ]
        status = "active" if vpn.get("active") else "not detected"
        return f"VPN {status}; interfaces {', '.join(interfaces) if interfaces else '—'}"
    if name == "proxy":
        proxy = value if isinstance(value, dict) else {}
        enabled = sorted(
            key[:-6]
            for key, setting in proxy.items()
            if key.endswith("Enable") and setting not in (0, "0", False, None, "")
        )
        return f"proxy {'enabled: ' + ', '.join(enabled) if enabled else 'not enabled'}"
    return fit(str(value), 120)


def capability_rows(report: Any) -> List[Dict[str, Any]]:
    """Normalize current and legacy adapter capability reports for the TUI."""

    if not isinstance(report, dict):
        return []
    raw = report.get("capabilities", report)
    if not isinstance(raw, dict):
        return []
    rows: List[Dict[str, Any]] = []
    for name, status in raw.items():
        if not isinstance(status, dict) or "available" not in status:
            continue
        rows.append(
            {
                "name": str(name),
                "available": bool(status.get("available")),
                "requires_root": bool(status.get("requires_root")),
                "description": str(status.get("description") or ""),
                "missing_tools": [str(item) for item in status.get("missing_tools", [])],
            }
        )
    return sorted(rows, key=lambda item: (not item["available"], item["name"]))


def diagnostic_health(
    capabilities: Any, command_diagnostics: Any, parser_diagnostics: Any
) -> Dict[str, int]:
    rows = capability_rows(capabilities)
    commands = command_diagnostics if isinstance(command_diagnostics, list) else []
    parsers = parser_diagnostics if isinstance(parser_diagnostics, list) else []
    return {
        "capabilities_available": sum(bool(item["available"]) for item in rows),
        "capabilities_total": len(rows),
        "command_failures": sum(item.get("ok") is False for item in commands if isinstance(item, dict)),
        "command_warnings": sum(bool(item.get("warning_kind")) for item in commands if isinstance(item, dict)),
        "parser_warnings": sum(bool(item.get("warnings")) for item in parsers if isinstance(item, dict)),
        "parser_low_confidence": sum(
            str(item.get("confidence", "")).lower() in ("low", "unknown")
            for item in parsers
            if isinstance(item, dict)
        ),
    }


@dataclass
class LiveEvent:
    timestamp: str
    kind: str
    process: str
    target: str
    event_type: str = "connection.changed"
    source: str = "system.connections"
    severity: str = "info"
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def search_text(self) -> str:
        return " ".join(
            (
                self.timestamp,
                self.kind,
                self.process,
                self.target,
                self.event_type,
                self.source,
                self.severity,
                self.summary,
            )
        ).lower()


@dataclass
class LiveState:
    adapter: MacOSAdapter
    process_filter: Optional[str] = None
    tab: int = 0
    selection: int = 0
    scroll: int = 0
    query: str = ""
    sort_mode: str = "process"
    paused: bool = False
    show_help: bool = False
    show_detail: bool = False
    show_closed: bool = False
    connections: List[Connection] = field(default_factory=list)
    interfaces: List[Interface] = field(default_factory=list)
    routes: List[Dict[str, str]] = field(default_factory=list)
    resolvers: List[Dict[str, Any]] = field(default_factory=list)
    vpn: Dict[str, Any] = field(default_factory=dict)
    proxy: Dict[str, Any] = field(default_factory=dict)
    counters: Dict[str, Dict[str, int]] = field(default_factory=dict)
    rates: Dict[str, Dict[str, float]] = field(default_factory=dict)
    history_rx: Deque[float] = field(default_factory=lambda: deque(maxlen=60))
    history_tx: Deque[float] = field(default_factory=lambda: deque(maxlen=60))
    events: Deque[LiveEvent] = field(default_factory=lambda: deque(maxlen=500))
    network_fingerprints: Dict[str, str] = field(default_factory=dict)
    network_values: Dict[str, Any] = field(default_factory=dict)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    command_health: List[Dict[str, Any]] = field(default_factory=list)
    parser_health: List[Dict[str, Any]] = field(default_factory=list)
    health_error: str = ""
    marker_count: int = 0
    opened_total: int = 0
    closed_total: int = 0
    refresh_count: int = 0
    last_refresh: float = 0.0
    last_counter_time: float = 0.0
    last_updated: str = "—"
    collection_ms: float = 0.0
    error: str = ""
    notice: str = ""
    resolved_names: Dict[str, str] = field(default_factory=dict)
    route_details: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def add_event(self, event: LiveEvent) -> None:
        self.events.appendleft(event)

    def observe_network_state(self, name: str, value: Any, timestamp: Optional[str] = None) -> bool:
        """Record the initial snapshot or a changed network state.

        Returns True when an event was added, which keeps this helper easy to
        test independently from curses and native commands.
        """

        fingerprint = stable_fingerprint(value)
        previous_fingerprint = self.network_fingerprints.get(name)
        if previous_fingerprint == fingerprint:
            return False
        current_value = copy.deepcopy(value)
        previous_value = copy.deepcopy(self.network_values.get(name))
        event_suffix = "snapshot" if previous_fingerprint is None else "changed"
        summary = network_state_summary(name, current_value)
        self.add_event(
            LiveEvent(
                timestamp=timestamp or utc_now(),
                kind="●" if previous_fingerprint is None else "~",
                process=name.upper(),
                target=summary,
                event_type=f"network.{name}.{event_suffix}",
                source=f"system.{name}",
                severity="info" if previous_fingerprint is None else "notice",
                summary=summary,
                details={
                    "previous": previous_value,
                    "current": current_value,
                    "previous_fingerprint": previous_fingerprint,
                    "fingerprint": fingerprint,
                },
            )
        )
        self.network_fingerprints[name] = fingerprint
        self.network_values[name] = current_value
        return True

    def refresh_health(self) -> None:
        """Read optional structured health APIs without requiring new adapters."""

        try:
            capabilities = getattr(self.adapter, "capabilities", None)
            commands = getattr(self.adapter, "command_diagnostics", None)
            parsers = getattr(self.adapter, "parser_diagnostics", None)
            self.capabilities = capabilities() if callable(capabilities) else {}
            self.command_health = commands() if callable(commands) else []
            self.parser_health = parsers() if callable(parsers) else []
            if not isinstance(self.capabilities, dict):
                self.capabilities = {}
            if not isinstance(self.command_health, list):
                self.command_health = []
            if not isinstance(self.parser_health, list):
                self.parser_health = []
            self.health_error = ""
        except Exception as exc:
            # Health is advisory: a third-party/older adapter must not take
            # down the live dashboard merely because this API is absent or bad.
            self.health_error = str(exc)[:160]

    def filtered_events(self) -> List[LiveEvent]:
        values = list(self.events)
        if self.query:
            query = self.query.lower()
            values = [item for item in values if query in item.search_text()]
        return values

    def selected_event(self) -> Optional[LiveEvent]:
        values = self.filtered_events()
        if not values:
            return None
        self.selection = max(0, min(self.selection, len(values) - 1))
        return values[self.selection]

    def add_marker(self, message: str = "User marker") -> LiveEvent:
        message = message.strip() or "User marker"
        self.marker_count += 1
        event = LiveEvent(
            timestamp=utc_now(),
            kind="◆",
            process="USER",
            target=message,
            event_type="user.marker",
            source="user",
            severity="notice",
            summary=message,
            details={"message": message, "marker_number": self.marker_count},
        )
        self.add_event(event)
        self.notice = f"Marker #{self.marker_count}: {message}"
        return event

    def refresh(self, force_static: bool = False) -> None:
        if self.paused:
            return
        started = time.monotonic()
        try:
            previous = {item.key(): item for item in self.connections}
            current_values = self.adapter.connections()
            if self.process_filter:
                current_values = [item for item in current_values if self.process_filter.lower() in item.process.lower()]
            current = {item.key(): item for item in current_values}
            now_label = utc_now()
            if self.refresh_count > 0:
                for key in current.keys() - previous.keys():
                    item = current[key]
                    target = connection_target(item)
                    self.add_event(
                        LiveEvent(
                            now_label,
                            "+",
                            item.process,
                            target,
                            event_type="connection.opened",
                            summary=f"{item.process} opened {target}",
                            details=item.to_dict(),
                        )
                    )
                    self.opened_total += 1
                for key in previous.keys() - current.keys():
                    item = previous[key]
                    target = connection_target(item)
                    self.add_event(
                        LiveEvent(
                            now_label,
                            "−",
                            item.process,
                            target,
                            event_type="connection.closed",
                            summary=f"{item.process} closed {target}",
                            details=item.to_dict(),
                        )
                    )
                    self.closed_total += 1
            self.connections = list(current.values())

            new_counters = self.adapter.interface_counters()
            counter_time = time.monotonic()
            if self.counters and self.last_counter_time and new_counters:
                elapsed = max(0.001, counter_time - self.last_counter_time)
                rates: Dict[str, Dict[str, float]] = {}
                for name, values in new_counters.items():
                    old = self.counters.get(name, {})
                    rates[name] = {
                        "rx": max(0.0, (values.get("rx_bytes", 0) - old.get("rx_bytes", values.get("rx_bytes", 0))) / elapsed),
                        "tx": max(0.0, (values.get("tx_bytes", 0) - old.get("tx_bytes", values.get("tx_bytes", 0))) / elapsed),
                    }
                self.rates = rates
                self.history_rx.append(sum(value["rx"] for value in rates.values()))
                self.history_tx.append(sum(value["tx"] for value in rates.values()))
            self.counters = new_counters
            self.last_counter_time = counter_time

            if force_static or self.refresh_count % 3 == 0:
                self.interfaces = self.adapter.interfaces()
                self.routes = self.adapter.routes()
                self.resolvers = self.adapter.dns_resolvers()
                self.vpn = self.adapter.vpn_status()
                self.proxy = self.adapter.proxy_config()
                self.observe_network_state("routes", self.routes, now_label)
                self.observe_network_state("dns", self.resolvers, now_label)
                self.observe_network_state("vpn", self.vpn, now_label)
                self.observe_network_state("proxy", self.proxy, now_label)
                self.refresh_health()
            self.refresh_count += 1
            self.last_updated = time.strftime("%H:%M:%S")
            self.last_refresh = time.monotonic()
            self.collection_ms = (self.last_refresh - started) * 1000
            self.error = ""
        except Exception as exc:  # keep the UI usable when one native sensor fails
            self.error = str(exc)[:200]
            self.last_refresh = time.monotonic()

    def filtered_connections(self) -> List[Connection]:
        values = self.connections if self.show_closed else [item for item in self.connections if item.state != "CLOSED"]
        if self.query:
            query = self.query.lower()
            values = [
                item
                for item in values
                if query
                in " ".join(
                    (
                        item.process,
                        str(item.pid),
                        item.protocol,
                        item.local.display(),
                        item.remote.display() if item.remote else "",
                        item.state,
                        item.path,
                    )
                ).lower()
            ]
        if self.sort_mode == "remote":
            return sorted(values, key=lambda item: (connection_target(item), item.process, item.pid))
        if self.sort_mode == "state":
            return sorted(values, key=lambda item: (item.state, item.process, item.pid))
        if self.sort_mode == "pid":
            return sorted(values, key=lambda item: (item.pid, item.process, connection_target(item)))
        return sorted(values, key=lambda item: (item.process.lower(), item.pid, connection_target(item)))

    def selected_connection(self) -> Optional[Connection]:
        values = self.filtered_connections()
        if not values:
            return None
        self.selection = max(0, min(self.selection, len(values) - 1))
        return values[self.selection]

    def export(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path(f"wirescope-live-{timestamp}.json")
        report = {
            "timestamp": utc_now(),
            "connections": [item.to_dict() for item in self.connections],
            "interfaces": [item.to_dict() for item in self.interfaces],
            "routes": self.routes,
            "dns": self.resolvers,
            "vpn": self.vpn,
            "proxy": self.proxy,
            "interface_counters": self.counters,
            "events": [event.__dict__ for event in self.events],
            "capabilities": self.capabilities,
            "command_diagnostics": self.command_health,
            "parser_diagnostics": self.parser_health,
        }
        atomic_write_text(path, json.dumps(report, ensure_ascii=False, indent=2))
        self.notice = f"Exported {path}"
        return str(path)

    def resolve_selected(self) -> None:
        item = self.selected_connection()
        if item is None or item.remote is None:
            self.notice = "Selected row has no remote endpoint"
            return
        host = item.remote.host.split("%", 1)[0]
        try:
            name = socket.gethostbyaddr(host)[0]
            self.resolved_names[host] = name
            self.notice = f"{host} → {name}"
        except OSError as exc:
            self.notice = f"No reverse DNS name for {host}: {exc}"

    def inspect_selected_route(self) -> None:
        item = self.selected_connection()
        if item is None or item.remote is None:
            self.notice = "Selected row has no remote endpoint"
            return
        host = item.remote.host.split("%", 1)[0]
        try:
            self.route_details[host] = self.adapter.route_for(host)
            route = self.route_details[host]
            self.notice = f"Route to {host}: {route.get('interface', '?')} → {route.get('gateway', '?')}"
        except Exception as exc:
            self.notice = f"Route lookup failed: {exc}"


def safe_add(window: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    height, width = window.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width:
        return
    try:
        window.addnstr(y, x, text, max(0, width - x - 1), attr)
    except curses.error:
        pass


def color(index: int) -> int:
    try:
        return curses.color_pair(index)
    except curses.error:
        return 0


def draw_header(screen: Any, state: LiveState) -> int:
    height, width = screen.getmaxyx()
    title = f" WireScope {__version__} "
    status = "PAUSED" if state.paused else f"LIVE {state.last_updated}"
    safe_add(screen, 0, 0, title, curses.A_BOLD | color(1))
    safe_add(screen, 0, max(len(title) + 1, width - len(status) - 2), status, curses.A_BOLD | color(3 if state.paused else 2))
    x = 1
    for index, tab in enumerate(TABS):
        label = f" {index + 1}:{tab} "
        attr = curses.A_REVERSE | curses.A_BOLD if index == state.tab else color(5)
        if x + len(label) < width:
            safe_add(screen, 2, x, label, attr)
        x += len(label) + 1
    safe_add(screen, 3, 0, "─" * max(0, width - 1), color(5))
    return 4


def draw_status(screen: Any, state: LiveState) -> None:
    height, width = screen.getmaxyx()
    message = state.error or state.notice
    if not message:
        message = "q quit  ←/→ tabs  ↑/↓ select  / filter  m marker  d details  p pause  e export  ? help"
    attr = color(4) | curses.A_BOLD if state.error else color(5)
    safe_add(screen, height - 1, 0, fit(" " + message, width - 1), attr)


def draw_overview(screen: Any, state: LiveState, top: int) -> None:
    height, width = screen.getmaxyx()
    remote = [item for item in state.connections if item.remote]
    listening = [item for item in state.connections if item.state == "LISTEN"]
    tcp = sum(item.protocol == "TCP" for item in remote)
    udp = sum(item.protocol == "UDP" for item in remote)
    vpn_active = bool(state.vpn.get("active"))
    stats = [
        ("CONNECTIONS", str(len(state.connections)), 1),
        ("REMOTE", str(len(remote)), 2),
        ("LISTEN", str(len(listening)), 3),
        ("TCP", str(tcp), 1),
        ("UDP/QUIC", str(udp), 1),
        ("VPN", "ACTIVE" if vpn_active else "OFF", 2 if vpn_active else 4),
    ]
    card_width = max(14, (width - 2) // max(1, min(len(stats), 6)))
    for index, (label, value, pair) in enumerate(stats):
        x = 1 + index * card_width
        if x >= width - 5:
            break
        safe_add(screen, top, x, label, color(5))
        safe_add(screen, top + 1, x, value, curses.A_BOLD | color(pair))

    rx = sum(item.get("rx", 0.0) for item in state.rates.values())
    tx = sum(item.get("tx", 0.0) for item in state.rates.values())
    safe_add(screen, top + 3, 1, "TRAFFIC", curses.A_BOLD | color(1))
    safe_add(screen, top + 4, 1, f"↓ {format_rate(rx):>12}  {sparkline(state.history_rx, max(8, min(30, width // 4)))}", color(2))
    safe_add(screen, top + 5, 1, f"↑ {format_rate(tx):>12}  {sparkline(state.history_tx, max(8, min(30, width // 4)))}", color(3))
    safe_add(screen, top + 6, 1, f"Opened {state.opened_total} · Closed {state.closed_total} · collection {state.collection_ms:.0f}ms", color(5))

    split = max(35, width // 2)
    process_counts = Counter(item.process for item in remote)
    safe_add(screen, top + 3, split, "TOP PROCESSES", curses.A_BOLD | color(1))
    for index, (name, count) in enumerate(process_counts.most_common(max(3, min(8, height - top - 11)))):
        safe_add(screen, top + 4 + index, split, f"{fit(name, 22):22} {count:>5} connections")

    event_top = top + 9
    health = diagnostic_health(state.capabilities, state.command_health, state.parser_health)
    available = health["capabilities_available"]
    total = health["capabilities_total"]
    health_text = (
        f"SENSORS {available}/{total}  command failures {health['command_failures']}  "
        f"warnings {health['command_warnings']}  parser low-confidence {health['parser_low_confidence']}"
        if total
        else "SENSORS health API unavailable (legacy adapter)"
    )
    safe_add(screen, event_top, 1, health_text, color(3) if health["command_failures"] else color(5))
    event_top += 2
    split_events = width >= 104
    event_width = max(20, (width // 2) - 3) if split_events else max(20, width - 3)
    safe_add(screen, event_top, 1, "RECENT TIMELINE EVENTS", curses.A_BOLD | color(1))
    visible_rows = max(1, height - event_top - 3)
    for index, event in enumerate(list(state.events)[:visible_rows]):
        pair = 2 if event.kind == "+" else (4 if event.kind == "−" else 3 if event.severity == "notice" else 5)
        label = f"{event_time_label(event.timestamp)} {event.kind} {fit(event.event_type, 24)} {event.summary or event.target}"
        safe_add(screen, event_top + 1 + index, 1, fit(label, event_width), color(pair))
    if not state.events:
        safe_add(screen, event_top + 1, 1, "Waiting for changes…", color(5))

    if split_events:
        health_x = width // 2 + 1
        safe_add(screen, event_top, health_x, "CAPABILITY HEALTH", curses.A_BOLD | color(1))
        rows = capability_rows(state.capabilities)
        for index, item in enumerate(rows[:visible_rows]):
            marker = "OK" if item["available"] else "MISS"
            root = " root" if item["requires_root"] else ""
            line = f"{marker:4} {item['name']}{root}"
            safe_add(screen, event_top + 1 + index, health_x, line, color(2 if item["available"] else 4))
        if state.health_error:
            safe_add(screen, event_top + 1, health_x, "Health: " + state.health_error, color(4))


def draw_connections(screen: Any, state: LiveState, top: int) -> None:
    height, width = screen.getmaxyx()
    values = state.filtered_connections()
    available = max(1, height - top - 3 - (10 if state.show_detail else 0))
    state.selection = max(0, min(state.selection, max(0, len(values) - 1)))
    if state.selection < state.scroll:
        state.scroll = state.selection
    elif state.selection >= state.scroll + available:
        state.scroll = state.selection - available + 1
    query = f" filter={state.query!r}" if state.query else ""
    safe_add(screen, top, 1, f"{len(values)}/{len(state.connections)} sockets · sort={state.sort_mode} · closed={'shown' if state.show_closed else 'hidden'}{query}", color(5))
    remote_width = max(20, width - 70)
    safe_add(screen, top + 1, 1, f"{'PROCESS':16} {'PID':>7} {'PROTO':5} {'REMOTE':{remote_width}} {'STATE':13} PATH", curses.A_BOLD)
    for row, item in enumerate(values[state.scroll : state.scroll + available]):
        absolute = state.scroll + row
        target = item.remote.display() if item.remote else item.local.display()
        text = f"{fit(item.process, 16):16} {item.pid:>7} {item.protocol:5} {fit(target, remote_width):{remote_width}} {fit(item.state or '—', 13):13} {item.path}"
        attr = curses.A_REVERSE if absolute == state.selection else 0
        if item.state == "CLOSED":
            attr |= color(4)
        elif item.remote:
            attr |= color(2)
        safe_add(screen, top + 2 + row, 1, text, attr)
    if not values:
        safe_add(screen, top + 3, 2, "No matching connections", color(3))
    if state.show_detail:
        item = state.selected_connection()
        detail_top = height - 11
        safe_add(screen, detail_top, 0, "─" * max(0, width - 1), color(5))
        safe_add(screen, detail_top + 1, 1, "CONNECTION DETAILS", curses.A_BOLD | color(1))
        if item:
            details = [
                f"Process: {item.process}  PID: {item.pid}  User: {item.user}  FD: {item.fd}",
                f"Protocol: {item.protocol}/{item.family}  State: {item.state or '—'}  Path: {item.path}",
                f"Local: {item.local.display()}",
                f"Remote: {item.remote.display() if item.remote else '—'}",
            ]
            if item.remote:
                host = item.remote.host.split("%", 1)[0]
                details.append(f"Reverse DNS: {state.resolved_names.get(host, 'press n to resolve')}")
                route = state.route_details.get(host)
                details.append(
                    f"Effective route: {route.get('interface', '?')} → {route.get('gateway', '?')} (MTU {route.get('mtu', '?')})"
                    if route
                    else "Effective route: press g to inspect"
                )
            for offset, line in enumerate(details):
                safe_add(screen, detail_top + 2 + offset, 2, line)


def process_rows(connections: Iterable[Connection]) -> List[Dict[str, Any]]:
    rows: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for item in connections:
        key = (item.process, item.pid)
        row = rows.setdefault(key, {"process": item.process, "pid": item.pid, "total": 0, "remote": 0, "tcp": 0, "udp": 0, "listen": 0, "targets": set()})
        row["total"] += 1
        row["remote"] += int(item.remote is not None)
        row["tcp"] += int(item.protocol == "TCP")
        row["udp"] += int(item.protocol == "UDP")
        row["listen"] += int(item.state == "LISTEN")
        if item.remote:
            row["targets"].add(item.remote.host)
    return sorted(rows.values(), key=lambda row: (-row["remote"], -row["total"], row["process"].lower()))


def draw_processes(screen: Any, state: LiveState, top: int) -> None:
    height, width = screen.getmaxyx()
    rows = process_rows(state.connections)
    safe_add(screen, top, 1, f"{len(rows)} processes owning network sockets", color(5))
    safe_add(screen, top + 1, 1, f"{'PROCESS':22} {'PID':>7} {'ALL':>6} {'REMOTE':>7} {'TCP':>6} {'UDP':>6} {'LISTEN':>7} UNIQUE TARGETS", curses.A_BOLD)
    for index, row in enumerate(rows[: max(1, height - top - 3)]):
        text = f"{fit(row['process'], 22):22} {row['pid']:>7} {row['total']:>6} {row['remote']:>7} {row['tcp']:>6} {row['udp']:>6} {row['listen']:>7} {len(row['targets']):>14}"
        safe_add(screen, top + 2 + index, 1, text, color(2) if row["remote"] else 0)


def draw_interfaces(screen: Any, state: LiveState, top: int) -> None:
    height, width = screen.getmaxyx()
    safe_add(screen, top, 1, f"{'NAME':10} {'STATUS':10} {'MTU':>6} {'RX RATE':>13} {'TX RATE':>13} {'RX TOTAL':>12} {'TX TOTAL':>12} ADDRESSES", curses.A_BOLD)
    for index, item in enumerate(state.interfaces[: max(1, height - top - 2)]):
        rate = state.rates.get(item.name, {})
        totals = state.counters.get(item.name, {})
        addresses = ", ".join(item.ipv4 + item.ipv6)
        status = item.status if item.status != "unknown" else ("up" if "UP" in item.flags else "down")
        text = (
            f"{item.name:10} {status:10} {item.mtu or 0:>6} "
            f"{format_rate(rate.get('rx', 0)):>13} {format_rate(rate.get('tx', 0)):>13} "
            f"{format_bytes(totals.get('rx_bytes', 0)):>12} {format_bytes(totals.get('tx_bytes', 0)):>12} {addresses}"
        )
        attr = color(3) if item.is_vpn else (color(2) if status in ("active", "up") else color(5))
        safe_add(screen, top + 1 + index, 1, text, attr)


def draw_dns(screen: Any, state: LiveState, top: int) -> None:
    row = top
    safe_add(screen, row, 1, "SYSTEM RESOLVERS", curses.A_BOLD | color(1))
    row += 1
    if not state.resolvers:
        safe_add(screen, row, 2, "macOS did not expose resolver configuration", color(3))
        row += 1
    for resolver in state.resolvers:
        servers = ", ".join(resolver.get("nameservers", [])) or "scoped/system resolver"
        interface = resolver.get("if_index", "")
        safe_add(screen, row, 2, f"#{resolver.get('id', '?'):>2}  {servers}  {interface}")
        row += 1
        domains = resolver.get("search_domains", [])
        if domains:
            safe_add(screen, row, 6, "search: " + ", ".join(domains), color(5))
            row += 1
    row += 1
    safe_add(screen, row, 1, "SYSTEM PROXY", curses.A_BOLD | color(1))
    row += 1
    if not state.proxy:
        safe_add(screen, row, 2, "No system proxy configured", color(5))
    else:
        for key, value in state.proxy.items():
            safe_add(screen, row, 2, f"{key}: {value}")
            row += 1


def draw_vpn(screen: Any, state: LiveState, top: int) -> None:
    active = bool(state.vpn.get("active"))
    full = bool(state.vpn.get("full_tunnel_likely"))
    safe_add(screen, top, 1, f"VPN {'ACTIVE' if active else 'NOT DETECTED'}", curses.A_BOLD | color(2 if active else 4))
    safe_add(screen, top + 1, 1, f"Full tunnel likely: {'yes' if full else 'no / split tunnel'}")
    row = top + 3
    safe_add(screen, row, 1, f"{'INTERFACE':12} {'MTU':>7} ADDRESSES", curses.A_BOLD)
    row += 1
    for item in state.vpn.get("interfaces", []):
        addresses = ", ".join(item.get("ipv4", []) + item.get("ipv6", [])) or "—"
        safe_add(screen, row, 1, f"{item.get('name', ''):12} {item.get('mtu') or 0:>7} {addresses}", color(3))
        row += 1
    row += 1
    safe_add(screen, row, 1, "DEFAULT ROUTES", curses.A_BOLD)
    row += 1
    for route in state.vpn.get("default_routes", []):
        safe_add(screen, row, 2, f"{route.get('gateway')} via {route.get('interface')} ({route.get('flags')})")
        row += 1
    for warning in state.vpn.get("warnings", []):
        safe_add(screen, row + 1, 1, "⚠ " + warning, color(3) | curses.A_BOLD)
        row += 1


def draw_routes(screen: Any, state: LiveState, top: int) -> None:
    height, width = screen.getmaxyx()
    safe_add(screen, top, 1, f"{len(state.routes)} IPv4 routes", color(5))
    safe_add(screen, top + 1, 1, f"{'DESTINATION':24} {'GATEWAY':30} {'INTERFACE':12} FLAGS", curses.A_BOLD)
    for index, route in enumerate(state.routes[: max(1, height - top - 3)]):
        text = f"{fit(route.get('destination', ''), 24):24} {fit(route.get('gateway', ''), 30):30} {route.get('interface', ''):12} {route.get('flags', '')}"
        attr = color(3) if route.get("interface", "").startswith(("utun", "tun", "ppp", "wg")) else 0
        safe_add(screen, top + 2 + index, 1, text, attr)


def draw_timeline(screen: Any, state: LiveState, top: int) -> None:
    height, width = screen.getmaxyx()
    values = state.filtered_events()
    detail_visible = state.show_detail and height >= 18
    detail_height = 9 if detail_visible else 0
    available = max(1, height - top - 3 - detail_height)
    state.selection = max(0, min(state.selection, max(0, len(values) - 1)))
    if state.selection < state.scroll:
        state.scroll = state.selection
    elif state.selection >= state.scroll + available:
        state.scroll = state.selection - available + 1

    query = f" · filter={state.query!r}" if state.query else ""
    safe_add(
        screen,
        top,
        1,
        f"{len(values)}/{len(state.events)} events · newest first · markers {state.marker_count}{query}",
        color(5),
    )
    if width >= 92:
        type_width = min(30, max(20, width // 4))
        source_width = min(22, max(14, width // 6))
        summary_width = max(12, width - type_width - source_width - 19)
        safe_add(
            screen,
            top + 1,
            1,
            f"{'TIME':8} {'K':1} {'TYPE':{type_width}} {'SOURCE':{source_width}} SUMMARY",
            curses.A_BOLD,
        )
    else:
        type_width = min(25, max(16, width // 3))
        source_width = 0
        summary_width = max(10, width - type_width - 14)
        safe_add(screen, top + 1, 1, f"{'TIME':8} {'K':1} {'TYPE':{type_width}} SUMMARY", curses.A_BOLD)

    for row, event in enumerate(values[state.scroll : state.scroll + available]):
        absolute = state.scroll + row
        summary = event.summary or event.target
        if source_width:
            text = (
                f"{event_time_label(event.timestamp):8} {event.kind:1} "
                f"{fit(event.event_type, type_width):{type_width}} "
                f"{fit(event.source, source_width):{source_width}} {fit(summary, summary_width)}"
            )
        else:
            text = (
                f"{event_time_label(event.timestamp):8} {event.kind:1} "
                f"{fit(event.event_type, type_width):{type_width}} {fit(summary, summary_width)}"
            )
        attr = curses.A_REVERSE if absolute == state.selection else 0
        if event.kind == "+":
            attr |= color(2)
        elif event.kind == "−" or event.severity in ("error", "critical"):
            attr |= color(4)
        elif event.severity in ("notice", "warning"):
            attr |= color(3)
        else:
            attr |= color(5)
        safe_add(screen, top + 2 + row, 1, text, attr)
    if not values:
        safe_add(screen, top + 3, 2, "No matching timeline events", color(3))

    if detail_visible:
        event = state.selected_event()
        detail_top = height - 10
        safe_add(screen, detail_top, 0, "─" * max(0, width - 1), color(5))
        safe_add(screen, detail_top + 1, 1, "EVENT DETAILS", curses.A_BOLD | color(1))
        if event:
            safe_add(
                screen,
                detail_top + 2,
                2,
                f"{event.timestamp}  {event.event_type}  source={event.source}  severity={event.severity}",
            )
            safe_add(screen, detail_top + 3, 2, event.summary or event.target)
            detail_json = json.dumps(event.details, ensure_ascii=False, indent=2, sort_keys=True, default=str)
            for offset, line in enumerate(detail_json.splitlines()[:5]):
                safe_add(screen, detail_top + 4 + offset, 2, line, color(5))
    elif state.show_detail:
        safe_add(screen, height - 2, 1, "Event details need at least 18 terminal rows", color(3))


def draw_help(screen: Any) -> None:
    height, width = screen.getmaxyx()
    box_width = min(72, width - 4)
    lines = [
        "WireScope keyboard",
        "",
        "1–8 / ← → / h l    switch tabs",
        "↑ ↓ / j k / PgUp   select and scroll",
        "/                  filter connections/timeline",
        "m                  add timestamped user marker",
        "s                  cycle sort mode",
        "x                  show/hide CLOSED sockets",
        "d / Enter          selected connection/event details",
        "n                  reverse-DNS selected remote",
        "g                  inspect selected effective route",
        "p / Space          pause/resume refresh",
        "r                  refresh now",
        "e                  export current snapshot",
        "c                  clear filter, counters, and timeline",
        "q / Esc            close help or quit",
        "?                  toggle this help",
    ]
    box_height = len(lines) + 2
    top = max(1, (height - box_height) // 2)
    left = max(1, (width - box_width) // 2)
    try:
        window = screen.derwin(box_height, box_width, top, left)
        window.erase()
        window.box()
        for index, line in enumerate(lines):
            safe_add(window, index + 1, 2, line, curses.A_BOLD | color(1) if index == 0 else 0)
        window.refresh()
    except curses.error:
        pass


def prompt_filter(screen: Any, state: LiveState) -> None:
    height, width = screen.getmaxyx()
    prompt = "Filter: "
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    screen.timeout(-1)
    safe_add(screen, height - 1, 0, " " * max(0, width - 1))
    safe_add(screen, height - 1, 0, prompt, curses.A_BOLD)
    try:
        value = screen.getstr(height - 1, len(prompt), max(1, width - len(prompt) - 2))
        state.query = value.decode("utf-8", errors="replace").strip()
        state.selection = 0
        state.scroll = 0
    except curses.error:
        pass
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.timeout(100)


def prompt_marker(screen: Any, state: LiveState) -> None:
    height, width = screen.getmaxyx()
    prompt = "Marker: "
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    screen.timeout(-1)
    safe_add(screen, height - 1, 0, " " * max(0, width - 1))
    safe_add(screen, height - 1, 0, prompt, curses.A_BOLD)
    try:
        value = screen.getstr(height - 1, len(prompt), max(1, width - len(prompt) - 2))
        state.add_marker(value.decode("utf-8", errors="replace"))
        state.selection = 0
        state.scroll = 0
    except curses.error:
        pass
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.timeout(100)


def draw(screen: Any, state: LiveState) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    if height < 12 or width < 60:
        safe_add(screen, 0, 0, "WireScope needs a terminal of at least 60×12", color(3) | curses.A_BOLD)
        safe_add(screen, 1, 0, f"Current size: {width}×{height}")
        screen.refresh()
        return
    top = draw_header(screen, state)
    if state.tab == 0:
        draw_overview(screen, state, top)
    elif state.tab == 1:
        draw_connections(screen, state, top)
    elif state.tab == 2:
        draw_processes(screen, state, top)
    elif state.tab == 3:
        draw_interfaces(screen, state, top)
    elif state.tab == 4:
        draw_dns(screen, state, top)
    elif state.tab == 5:
        draw_vpn(screen, state, top)
    elif state.tab == 6:
        draw_routes(screen, state, top)
    else:
        draw_timeline(screen, state, top)
    draw_status(screen, state)
    if state.show_help:
        draw_help(screen)
    screen.refresh()


def run_curses(screen: Any, adapter: MacOSAdapter, interval: float, process: Optional[str]) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    curses.noecho()
    curses.cbreak()
    screen.keypad(True)
    screen.timeout(100)
    if curses.has_colors():
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        background = -1
        try:
            curses.init_pair(1, curses.COLOR_CYAN, background)
            curses.init_pair(2, curses.COLOR_GREEN, background)
            curses.init_pair(3, curses.COLOR_YELLOW, background)
            curses.init_pair(4, curses.COLOR_RED, background)
            curses.init_pair(5, curses.COLOR_BLUE, background)
        except curses.error:
            curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
            curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(5, curses.COLOR_BLUE, curses.COLOR_BLACK)
    state = LiveState(adapter=adapter, process_filter=process)
    state.refresh(force_static=True)
    sort_modes = ("process", "remote", "state", "pid")
    while True:
        if not state.paused and time.monotonic() - state.last_refresh >= interval:
            state.refresh()
        draw(screen, state)
        try:
            key = screen.getch()
        except KeyboardInterrupt:
            break
        if key == -1:
            continue
        state.notice = ""
        if state.show_help and key not in (ord("?"), ord("q"), 27):
            continue
        if key in (ord("q"), 27):
            if state.show_help:
                state.show_help = False
            else:
                break
        elif key == ord("?"):
            state.show_help = not state.show_help
        elif key in (curses.KEY_RIGHT, ord("l")):
            state.tab = (state.tab + 1) % len(TABS)
            state.selection = 0
            state.scroll = 0
            state.show_detail = False
        elif key in (curses.KEY_LEFT, ord("h")):
            state.tab = (state.tab - 1) % len(TABS)
            state.selection = 0
            state.scroll = 0
            state.show_detail = False
        elif ord("1") <= key <= ord(str(len(TABS))):
            state.tab = key - ord("1")
            state.selection = 0
            state.scroll = 0
            state.show_detail = False
        elif key in (curses.KEY_DOWN, ord("j")):
            state.selection += 1
        elif key in (curses.KEY_UP, ord("k")):
            state.selection = max(0, state.selection - 1)
        elif key == curses.KEY_NPAGE:
            state.selection += max(5, screen.getmaxyx()[0] - 10)
        elif key == curses.KEY_PPAGE:
            state.selection = max(0, state.selection - max(5, screen.getmaxyx()[0] - 10))
        elif key == ord("/"):
            prompt_filter(screen, state)
        elif key == ord("m"):
            prompt_marker(screen, state)
        elif key == ord("s"):
            state.sort_mode = sort_modes[(sort_modes.index(state.sort_mode) + 1) % len(sort_modes)]
        elif key == ord("x"):
            state.show_closed = not state.show_closed
            state.selection = 0
            state.scroll = 0
        elif key in (ord("d"), 10, 13):
            state.show_detail = not state.show_detail
        elif key == ord("n"):
            if state.tab == 1:
                state.resolve_selected()
            else:
                state.notice = "Reverse DNS is available on the Connections tab"
        elif key == ord("g"):
            if state.tab == 1:
                state.inspect_selected_route()
            else:
                state.notice = "Effective route lookup is available on the Connections tab"
        elif key in (ord("p"), ord(" ")):
            state.paused = not state.paused
        elif key == ord("r"):
            was_paused = state.paused
            state.paused = False
            state.refresh(force_static=True)
            state.paused = was_paused
        elif key == ord("e"):
            try:
                state.export()
            except OSError as exc:
                state.error = str(exc)
        elif key == ord("c"):
            state.query = ""
            state.opened_total = 0
            state.closed_total = 0
            state.events.clear()
            state.network_fingerprints.clear()
            state.network_values.clear()
            state.marker_count = 0
            state.selection = 0
            state.scroll = 0


def plain_snapshot(adapter: MacOSAdapter, process: Optional[str] = None) -> str:
    width, _height = shutil.get_terminal_size((120, 34))
    connections = adapter.connections()
    if process:
        connections = [item for item in connections if process.lower() in item.process.lower()]
    remote = [item for item in connections if item.remote is not None]
    vpn = adapter.vpn_status()
    protocols = Counter(item.protocol for item in remote)
    lines = [
        f"WireScope {__version__} · network snapshot",
        "═" * width,
        f"Connections {len(connections)} · Remote {len(remote)} · TCP {protocols.get('TCP', 0)} · UDP/QUIC {protocols.get('UDP', 0)} · VPN {'ACTIVE' if vpn.get('active') else 'OFF'}",
        f"{'PROCESS':16} {'PID':>7} {'PROTO':5} {'REMOTE':34} {'STATE':13} PATH",
        "─" * width,
    ]
    for item in remote[:25]:
        target = item.remote.display() if item.remote else "—"
        lines.append(f"{fit(item.process, 16):16} {item.pid:>7} {item.protocol:5} {fit(target, 34):34} {fit(item.state or '—', 13):13} {item.path}")
    return "\n".join(line[:width] for line in lines)


def live(adapter: MacOSAdapter, interval: float, process: Optional[str] = None, plain: bool = False) -> None:
    if plain or not sys.stdin.isatty() or not sys.stdout.isatty():
        print(plain_snapshot(adapter, process=process))
        return
    try:
        curses.wrapper(run_curses, adapter, interval, process)
    except KeyboardInterrupt:
        pass
