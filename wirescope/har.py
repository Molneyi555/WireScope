from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

from .redact import redact_url


def load_har(path: str, show_sensitive: bool = False) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be an array")
    requests: List[Dict[str, Any]] = []
    domains: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    mime_types: Counter[str] = Counter()
    total_body = 0
    total_transfer = 0
    total_time = 0.0
    failed = 0
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = str(request.get("url", ""))
        domain = urlsplit(url).hostname or "unknown"
        method = str(request.get("method", "?"))
        status = int(response.get("status", 0) or 0)
        protocol = str(response.get("httpVersion") or request.get("httpVersion") or "unknown")
        content = response.get("content", {})
        mime = str(content.get("mimeType") or "unknown").split(";", 1)[0]
        body_size = max(0, int(response.get("bodySize", 0) or 0))
        headers_size = max(0, int(response.get("headersSize", 0) or 0))
        transfer = body_size + headers_size
        duration = float(entry.get("time", 0) or 0)
        domains[domain] += 1
        methods[method] += 1
        statuses[str(status)] += 1
        protocols[protocol] += 1
        mime_types[mime] += 1
        total_body += body_size
        total_transfer += transfer
        total_time = max(total_time, duration)
        if status == 0 or status >= 400:
            failed += 1
        timings = entry.get("timings", {})
        requests.append(
            {
                "started": entry.get("startedDateTime"),
                "method": method,
                "url": redact_url(url, show_sensitive=show_sensitive),
                "domain": domain,
                "status": status,
                "protocol": protocol,
                "mime_type": mime,
                "duration_ms": round(duration, 2),
                "body_bytes": body_size,
                "transfer_bytes": transfer,
                "server_ip": entry.get("serverIPAddress"),
                "connection": entry.get("connection"),
                "timings": {key: value for key, value in timings.items() if isinstance(value, (int, float)) and value >= 0},
                "cache": entry.get("cache", {}),
            }
        )
    requests.sort(key=lambda item: item["duration_ms"], reverse=True)
    return {
        "source": str(path),
        "summary": {
            "requests": len(requests),
            "failed": failed,
            "domains": len(domains),
            "total_body_bytes": total_body,
            "total_transfer_bytes": total_transfer,
            "longest_request_ms": round(total_time, 2),
            "domain_counts": dict(domains.most_common()),
            "methods": dict(methods),
            "statuses": dict(statuses),
            "protocols": dict(protocols),
            "mime_types": dict(mime_types.most_common()),
        },
        "requests": requests,
    }

