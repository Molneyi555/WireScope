#!/usr/bin/env python3
"""Repeatable, dependency-free release benchmarks for WireScope core paths."""

from __future__ import annotations

import argparse
import json
import platform
import resource
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict

from wirescope import __version__
from wirescope.analyzer import analyze_recording
from wirescope.artifacts import atomic_write_text
from wirescope.report import generate_html_report
from wirescope.session import EventEnvelope, SessionStore, import_recording


def timed(operation: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    result = operation()
    return result, round(time.perf_counter() - started, 6)


def rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def make_har(path: Path, entries: int) -> None:
    values = []
    for index in range(entries):
        values.append(
            {
                "startedDateTime": f"2026-01-01T00:00:{index % 60:02d}Z",
                "time": 20 + index % 200,
                "request": {
                    "method": "GET",
                    "url": f"https://assets.example.com/resource-{index}.js",
                    "httpVersion": "HTTP/2",
                },
                "response": {
                    "status": 200,
                    "httpVersion": "HTTP/2",
                    "bodySize": 1024 + index % 8192,
                    "headersSize": 256,
                    "content": {"mimeType": "application/javascript"},
                },
                "timings": {"dns": 1, "connect": 2, "ssl": 1, "wait": 10, "receive": 6},
            }
        )
    path.write_text(json.dumps({"log": {"version": "1.2", "entries": values}}), encoding="utf-8")


def session_benchmark(path: Path, events: int) -> Dict[str, Any]:
    def write() -> None:
        with SessionStore(str(path)) as store:
            session_id = store.start_session(title="WireScope benchmark", source="benchmark")
            for index in range(events):
                store.add_event(
                    EventEnvelope(
                        event_type="benchmark.event",
                        source="benchmark",
                        payload={"index": index, "bucket": index % 100},
                    ),
                    session_id=session_id,
                )
                if index and index % 5000 == 0:
                    store.commit()
            store.finish_session(session_id, {"events": events})

    _unused, write_seconds = timed(write)

    def query() -> Dict[str, Any]:
        with SessionStore(str(path), read_only=True) as store:
            return {
                "timeline": len(store.timeline(limit=10000, reverse=True)),
                "summary": store.summary()["counts"],
            }

    query_result, query_seconds = timed(query)
    return {
        "events": events,
        "write_seconds": write_seconds,
        "query_seconds": query_seconds,
        "database_bytes": path.stat().st_size,
        "query_result": query_result,
    }


def import_benchmark(source: Path, destination: Path, events: int) -> Dict[str, Any]:
    with source.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps({"type": "session_start", "timestamp": "2026-01-01T00:00:00Z"}) + "\n")
        for index in range(events - 1):
            stream.write(
                json.dumps(
                    {
                        "type": "benchmark_event",
                        "timestamp": "2026-01-01T00:00:01Z",
                        "index": index,
                    }
                )
                + "\n"
            )
    result, seconds = timed(lambda: import_recording(str(source), str(destination)))
    return {
        "events": events,
        "seconds": seconds,
        "source_bytes": source.stat().st_size,
        "database_bytes": destination.stat().st_size,
        "imported_events": result["imported_events"],
    }


def analysis_benchmark(har_path: Path, report_path: Path, entries: int) -> Dict[str, Any]:
    make_har(har_path, entries)
    report, analyze_seconds = timed(lambda: analyze_recording(str(har_path)))
    _unused, report_seconds = timed(lambda: generate_html_report(report, str(report_path)))
    return {
        "entries": entries,
        "analyze_seconds": analyze_seconds,
        "report_seconds": report_seconds,
        "har_bytes": har_path.stat().st_size,
        "report_bytes": report_path.stat().st_size,
    }


def run(events: int, har_entries: int) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="wirescope-benchmark-") as directory:
        root = Path(directory)
        measurements = {
            "session": session_benchmark(root / "events.wsdb", events),
            "jsonl_import": import_benchmark(root / "events.jsonl", root / "import.wsdb", events),
            "har_analysis": analysis_benchmark(root / "large.har", root / "report.html", har_entries),
        }
    return {
        "schema_version": 1,
        "wirescope_version": __version__,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "parameters": {"events": events, "har_entries": har_entries},
        "measurements": measurements,
        "max_rss_bytes": rss_bytes(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100_000)
    parser.add_argument("--har-entries", type=int, default=10_000)
    parser.add_argument("--quick", action="store_true", help="use a small CI smoke workload")
    parser.add_argument("--output", "-o", help="optional JSON result path")
    args = parser.parse_args()
    events = 1_000 if args.quick else args.events
    har_entries = 250 if args.quick else args.har_entries
    if events < 1 or har_entries < 1:
        parser.error("event and HAR counts must be positive")
    result = run(events, har_entries)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        atomic_write_text(args.output, rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
