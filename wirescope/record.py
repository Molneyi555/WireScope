from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, Optional, TextIO

from .artifacts import private_text_stream
from .macos import MacOSAdapter
from .models import Connection, utc_now


def write_event(stream: TextIO, event: Dict[str, Any]) -> None:
    stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()


def record_connections(
    adapter: MacOSAdapter,
    output: str,
    duration: float,
    interval: float,
    process: Optional[str] = None,
) -> Dict[str, Any]:
    previous: Dict[str, Connection] = {}
    opened = 0
    closed = 0
    snapshots = 0
    started = time.monotonic()
    with private_text_stream(output) as stream:
        write_event(
            stream,
            {
                "type": "session_start",
                "timestamp": utc_now(),
                "version": 1,
                "duration_seconds": duration,
                "interval_seconds": interval,
                "process_filter": process,
            },
        )
        while time.monotonic() - started < duration:
            connections: Iterable[Connection] = adapter.connections()
            if process:
                connections = [item for item in connections if process.lower() in item.process.lower()]
            current = {item.key(): item for item in connections}
            timestamp = utc_now()
            for key in current.keys() - previous.keys():
                write_event(stream, {"type": "connection_open", "timestamp": timestamp, "connection": current[key].to_dict()})
                opened += 1
            for key in previous.keys() - current.keys():
                write_event(stream, {"type": "connection_close", "timestamp": timestamp, "connection": previous[key].to_dict()})
                closed += 1
            previous = current
            snapshots += 1
            remaining = duration - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(min(interval, remaining))
        summary = {"snapshots": snapshots, "opened": opened, "closed": closed, "active_at_end": len(previous)}
        write_event(stream, {"type": "session_end", "timestamp": utc_now(), "summary": summary})
    return summary
