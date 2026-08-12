from __future__ import annotations

import csv
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from .assessment import build_assessment_context, calculate_scorecard
from .artifacts import atomic_text_writer, atomic_write_text
from .har import load_har
from .models import utc_now
from .public_suffix import registrable_domain
from .tracker import classify_tracker, is_tracker


def base_domain(host: str) -> str:
    """Backward-compatible name for the PSL-derived registrable domain."""

    return registrable_domain(host)


def read_jsonl(path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    events: List[Dict[str, Any]] = []
    errors: List[str] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {number}: {exc}")
                continue
            if isinstance(value, dict):
                events.append(value)
            else:
                errors.append(f"line {number}: expected an object")
    return events, errors


def timing_delta(timing: Dict[str, Any], start_key: str, end_key: str) -> Optional[float]:
    start = timing.get(start_key)
    end = timing.get(end_key)
    if not isinstance(start, (int, float)) or not isinstance(end, (int, float)) or start < 0 or end < 0:
        return None
    return round(max(0.0, end - start), 2)


def new_request(params: Dict[str, Any], redirect_index: int = 0) -> Dict[str, Any]:
    request = params.get("request", {})
    url = str(request.get("url", ""))
    parsed = urlsplit(url)
    headers = request.get("headers", {}) if isinstance(request.get("headers"), dict) else {}
    initiator = params.get("initiator", {}) if isinstance(params.get("initiator"), dict) else {}
    return {
        "id": str(params.get("requestId", "")),
        "redirect_index": redirect_index,
        "url": url,
        "scheme": parsed.scheme,
        "domain": parsed.hostname or "unknown",
        "path": parsed.path or "/",
        "query_keys": sorted({key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)}),
        "method": str(request.get("method", "?")),
        "resource_type": str(params.get("type", "Other")),
        "document_url": str(params.get("documentURL", "")),
        "started_monotonic": params.get("timestamp"),
        "started_wall_time": params.get("wallTime"),
        "started_at": None,
        "duration_ms": None,
        "status": 0,
        "status_text": "",
        "protocol": "unknown",
        "mime_type": "unknown",
        "remote_ip": None,
        "remote_port": None,
        "connection_id": None,
        "connection_reused": False,
        "transfer_bytes": 0,
        "body_bytes": 0,
        "request_headers": headers,
        "response_headers": {},
        "has_post_data": bool(request.get("hasPostData") or request.get("postData")),
        "post_data": request.get("postData"),
        "initial_priority": request.get("initialPriority"),
        "referrer_policy": request.get("referrerPolicy"),
        "initiator_type": initiator.get("type"),
        "initiator": initiator,
        "from_cache": False,
        "from_service_worker": False,
        "from_prefetch_cache": False,
        "failed": False,
        "failure": None,
        "canceled": False,
        "blocked_reason": None,
        "security_state": None,
        "security_details": None,
        "timing": {},
        "redirect": False,
        "third_party": False,
        "tracker": False,
    }


def apply_response(item: Dict[str, Any], response: Dict[str, Any]) -> None:
    item["status"] = int(response.get("status", 0) or 0)
    item["status_text"] = str(response.get("statusText", ""))
    item["protocol"] = str(response.get("protocol") or "unknown")
    item["mime_type"] = str(response.get("mimeType") or "unknown").split(";", 1)[0]
    item["remote_ip"] = response.get("remoteIPAddress")
    item["remote_port"] = response.get("remotePort")
    item["connection_id"] = response.get("connectionId")
    item["connection_reused"] = bool(response.get("connectionReused"))
    item["response_headers"] = response.get("headers", {}) if isinstance(response.get("headers"), dict) else {}
    item["from_cache"] = bool(response.get("fromDiskCache") or response.get("fromPrefetchCache"))
    item["from_service_worker"] = bool(response.get("fromServiceWorker"))
    item["from_prefetch_cache"] = bool(response.get("fromPrefetchCache"))
    item["security_state"] = response.get("securityState")
    item["security_details"] = response.get("securityDetails")
    timing = response.get("timing", {}) if isinstance(response.get("timing"), dict) else {}
    item["timing"] = {
        "queueing_ms": timing_delta(timing, "proxyStart", "proxyEnd"),
        "dns_ms": timing_delta(timing, "dnsStart", "dnsEnd"),
        "connect_ms": timing_delta(timing, "connectStart", "connectEnd"),
        "ssl_ms": timing_delta(timing, "sslStart", "sslEnd"),
        "worker_ms": timing_delta(timing, "workerStart", "workerReady"),
        "send_ms": timing_delta(timing, "sendStart", "sendEnd"),
        "ttfb_ms": round(float(timing.get("receiveHeadersEnd", 0)), 2) if isinstance(timing.get("receiveHeadersEnd"), (int, float)) and timing.get("receiveHeadersEnd", -1) >= 0 else None,
    }


def normalize_requests(requests: List[Dict[str, Any]]) -> None:
    starts = [item["started_monotonic"] for item in requests if isinstance(item.get("started_monotonic"), (int, float))]
    first_start = min(starts) if starts else 0.0
    document_hosts = [urlsplit(str(item.get("document_url") or "")).hostname for item in requests]
    primary_host = next((host for host in document_hosts if host), None)
    primary_source = "document_url"
    if primary_host is None and requests:
        primary_host = requests[0].get("domain")
        primary_source = "first_request_inference"
    primary_base = base_domain(primary_host or "")
    for item in requests:
        wall_time = item.get("started_wall_time")
        if isinstance(wall_time, (int, float)):
            item["started_at"] = datetime.fromtimestamp(wall_time, timezone.utc).isoformat(timespec="milliseconds")
        start = item.get("started_monotonic")
        item["offset_ms"] = round((start - first_start) * 1000, 2) if isinstance(start, (int, float)) else 0.0
        request_base = base_domain(str(item.get("domain") or ""))
        item["registrable_domain"] = request_base
        item["primary_registrable_domain"] = primary_base
        item["third_party"] = bool(primary_base and request_base and request_base != primary_base)
        item["third_party_confidence"] = "high" if primary_source == "document_url" else "low"
        item["third_party_basis"] = "public-suffix-list-etld-plus-one"
        tracker_match = classify_tracker(str(item.get("url") or ""), str(item.get("domain") or ""))
        item["tracker_match"] = tracker_match
        item["tracker"] = tracker_match is not None
        body = item.get("body_bytes", 0) or 0
        transfer = item.get("transfer_bytes", 0) or 0
        item["compression_ratio"] = round(body / transfer, 2) if transfer and body > transfer else None


def analyze_cdp_events(events: Sequence[Dict[str, Any]], parse_errors: Optional[List[str]] = None) -> Dict[str, Any]:
    current: Dict[str, Dict[str, Any]] = {}
    requests: List[Dict[str, Any]] = []
    lifecycle: List[Dict[str, Any]] = []
    websocket = {"opened": 0, "closed": 0, "sent_frames": 0, "received_frames": 0, "sent_bytes": 0, "received_bytes": 0}
    performance_metrics: Dict[str, float] = {}
    session_summary: Dict[str, Any] = {}
    source_metadata: Dict[str, Any] = {}
    pending_request_headers: Dict[str, Dict[str, Any]] = {}
    pending_response_headers: Dict[str, Dict[str, Any]] = {}

    for event in events:
        event_type = event.get("type")
        if event_type == "session_start":
            source_metadata = event
            continue
        if event_type == "session_end":
            session_summary = event.get("summary", {})
            continue
        if event_type == "cdp_command_result" and event.get("command") == "Performance.getMetrics":
            result = event.get("result") or {}
            for metric in result.get("metrics", []):
                if isinstance(metric, dict) and isinstance(metric.get("value"), (int, float)):
                    performance_metrics[str(metric.get("name"))] = metric["value"]
            continue
        if event_type != "cdp_event":
            continue
        method = event.get("method", "")
        params = event.get("params", {}) if isinstance(event.get("params"), dict) else {}
        request_id = str(params.get("requestId", ""))
        if method == "Network.requestWillBeSent":
            previous = current.get(request_id)
            redirect_response = params.get("redirectResponse")
            redirect_index = 0
            if previous is not None:
                redirect_index = int(previous.get("redirect_index", 0)) + 1
                if isinstance(redirect_response, dict):
                    apply_response(previous, redirect_response)
                    previous["redirect"] = True
                    end = params.get("timestamp")
                    start = previous.get("started_monotonic")
                    if isinstance(end, (int, float)) and isinstance(start, (int, float)):
                        previous["duration_ms"] = round(max(0.0, end - start) * 1000, 2)
            item = new_request(params, redirect_index=redirect_index)
            if request_id in pending_request_headers:
                item["request_headers"].update(pending_request_headers.pop(request_id))
            current[request_id] = item
            requests.append(item)
        elif method == "Network.requestWillBeSentExtraInfo":
            headers = params.get("headers", {}) if isinstance(params.get("headers"), dict) else {}
            if request_id in current:
                current[request_id]["request_headers"].update(headers)
                current[request_id]["associated_cookies"] = params.get("associatedCookies")
            else:
                pending_request_headers[request_id] = headers
        elif method == "Network.responseReceived":
            if request_id in current:
                apply_response(current[request_id], params.get("response", {}))
                if request_id in pending_response_headers:
                    current[request_id]["response_headers"].update(pending_response_headers.pop(request_id))
        elif method == "Network.responseReceivedExtraInfo":
            headers = params.get("headers", {}) if isinstance(params.get("headers"), dict) else {}
            if request_id in current:
                current[request_id]["response_headers"].update(headers)
            else:
                pending_response_headers[request_id] = headers
        elif method == "Network.requestServedFromCache":
            if request_id in current:
                current[request_id]["from_cache"] = True
        elif method == "Network.dataReceived":
            if request_id in current:
                current[request_id]["body_bytes"] += int(params.get("dataLength", 0) or 0)
        elif method == "Network.loadingFinished":
            if request_id in current:
                item = current[request_id]
                item["transfer_bytes"] = int(params.get("encodedDataLength", 0) or 0)
                end = params.get("timestamp")
                start = item.get("started_monotonic")
                if isinstance(end, (int, float)) and isinstance(start, (int, float)):
                    item["duration_ms"] = round(max(0.0, end - start) * 1000, 2)
        elif method == "Network.loadingFailed":
            if request_id in current:
                item = current[request_id]
                item["failed"] = True
                item["failure"] = params.get("errorText")
                item["canceled"] = bool(params.get("canceled"))
                item["blocked_reason"] = params.get("blockedReason")
                end = params.get("timestamp")
                start = item.get("started_monotonic")
                if isinstance(end, (int, float)) and isinstance(start, (int, float)):
                    item["duration_ms"] = round(max(0.0, end - start) * 1000, 2)
        elif method in ("Page.lifecycleEvent", "Page.loadEventFired", "Page.domContentEventFired"):
            lifecycle.append({"method": method, **params})
        elif method == "Network.webSocketCreated":
            websocket["opened"] += 1
        elif method == "Network.webSocketClosed":
            websocket["closed"] += 1
        elif method in ("Network.webSocketFrameSent", "Network.webSocketFrameReceived"):
            response = params.get("response", {})
            payload = response.get("payloadData", "") if isinstance(response, dict) else ""
            size = len(payload.encode("utf-8")) if isinstance(payload, str) else 0
            if method.endswith("Sent"):
                websocket["sent_frames"] += 1
                websocket["sent_bytes"] += size
            else:
                websocket["received_frames"] += 1
                websocket["received_bytes"] += size
    normalize_requests(requests)
    report = build_report(requests, "chrome-cdp", source_metadata, parse_errors or [])
    report["browser"] = {
        "lifecycle": lifecycle,
        "performance_metrics": performance_metrics,
        "websocket": websocket,
        "recorder_summary": session_summary,
    }
    return finalize_report(report)


def normalize_har(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    values = []
    for index, item in enumerate(report.get("requests", [])):
        url = item.get("url", "")
        parsed = urlsplit(url)
        timings = item.get("timings", {})
        values.append(
            {
                "id": f"har-{index}",
                "redirect_index": 0,
                "url": url,
                "scheme": parsed.scheme,
                "domain": item.get("domain") or parsed.hostname or "unknown",
                "path": parsed.path or "/",
                "query_keys": sorted({key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)}),
                "method": item.get("method", "?"),
                "resource_type": item.get("mime_type", "unknown"),
                "document_url": "",
                "started_at": item.get("started"),
                "started_monotonic": None,
                "started_wall_time": None,
                "offset_ms": 0,
                "duration_ms": item.get("duration_ms", 0),
                "status": item.get("status", 0),
                "status_text": "",
                "protocol": item.get("protocol", "unknown"),
                "mime_type": item.get("mime_type", "unknown"),
                "remote_ip": item.get("server_ip"),
                "remote_port": None,
                "connection_id": item.get("connection"),
                "connection_reused": False,
                "transfer_bytes": item.get("transfer_bytes", 0),
                "body_bytes": item.get("body_bytes", 0),
                "request_headers": {},
                "response_headers": {},
                "has_post_data": False,
                "post_data": None,
                "initial_priority": None,
                "referrer_policy": None,
                "initiator_type": None,
                "initiator": {},
                "from_cache": bool(item.get("cache")),
                "from_service_worker": False,
                "from_prefetch_cache": False,
                "failed": item.get("status", 0) == 0,
                "failure": None,
                "canceled": False,
                "blocked_reason": None,
                "security_state": None,
                "security_details": None,
                "timing": {
                    "queueing_ms": timings.get("blocked"),
                    "dns_ms": timings.get("dns"),
                    "connect_ms": timings.get("connect"),
                    "ssl_ms": timings.get("ssl"),
                    "send_ms": timings.get("send"),
                    "ttfb_ms": timings.get("wait"),
                    "receive_ms": timings.get("receive"),
                },
                "redirect": False,
                "third_party": False,
                "tracker": False,
                "compression_ratio": None,
            }
        )
    normalize_requests(values)
    return values


def build_report(requests: List[Dict[str, Any]], source_type: str, metadata: Dict[str, Any], parse_errors: List[str]) -> Dict[str, Any]:
    domains: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"requests": 0, "bytes": 0, "errors": 0, "third_party": False, "tracker": False})
    resource_types: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    mime_types: Counter[str] = Counter()
    tracker_categories: Counter[str] = Counter()
    tracker_rules: Counter[str] = Counter()
    total_bytes = 0
    total_body = 0
    failed = 0
    http_errors = 0
    cached = 0
    third_party = 0
    trackers = 0
    max_end = 0.0
    url_counts: Counter[str] = Counter()
    for item in requests:
        domain = item.get("domain") or "unknown"
        transfer = int(item.get("transfer_bytes", 0) or 0)
        body = int(item.get("body_bytes", 0) or 0)
        status = int(item.get("status", 0) or 0)
        duration = float(item.get("duration_ms", 0) or 0)
        offset = float(item.get("offset_ms", 0) or 0)
        domain_row = domains[domain]
        domain_row["requests"] += 1
        domain_row["bytes"] += transfer
        domain_row["errors"] += int(item.get("failed") or status >= 400)
        domain_row["third_party"] = domain_row["third_party"] or bool(item.get("third_party"))
        domain_row["tracker"] = domain_row["tracker"] or bool(item.get("tracker"))
        resource_types[str(item.get("resource_type") or "Other")] += 1
        protocols[str(item.get("protocol") or "unknown")] += 1
        statuses[str(status)] += 1
        methods[str(item.get("method") or "?")] += 1
        mime_types[str(item.get("mime_type") or "unknown")] += 1
        total_bytes += transfer
        total_body += body
        failed += int(bool(item.get("failed")))
        http_errors += int(status >= 400)
        cached += int(bool(item.get("from_cache")))
        third_party += int(bool(item.get("third_party")))
        trackers += int(bool(item.get("tracker")))
        tracker_match = item.get("tracker_match")
        if isinstance(tracker_match, dict):
            tracker_categories[str(tracker_match.get("category") or "unknown")] += 1
            tracker_rules[str(tracker_match.get("rule_id") or "unknown")] += 1
        max_end = max(max_end, offset + duration)
        url_counts[str(item.get("url", ""))] += 1
    sorted_domains = dict(sorted(domains.items(), key=lambda pair: (-pair[1]["bytes"], -pair[1]["requests"], pair[0])))
    summary = {
        "requests": len(requests),
        "domains": len(domains),
        "transfer_bytes": total_bytes,
        "body_bytes": total_body,
        "page_span_ms": round(max_end, 2),
        "failed": failed,
        "http_errors": http_errors,
        "cached": cached,
        "cache_percent": round(cached / len(requests) * 100, 1) if requests else 0,
        "third_party": third_party,
        "third_party_percent": round(third_party / len(requests) * 100, 1) if requests else 0,
        "trackers": trackers,
        "duplicate_requests": sum(count - 1 for count in url_counts.values() if count > 1),
        "redirects": sum(bool(item.get("redirect")) for item in requests),
        "slow_requests": sum((item.get("duration_ms") or 0) >= 1000 for item in requests),
        "large_requests": sum((item.get("transfer_bytes") or 0) >= 1_000_000 for item in requests),
    }
    return {
        "schema_version": 2,
        "generated_at": utc_now(),
        "source_type": source_type,
        "source_metadata": metadata,
        "parse_errors": parse_errors,
        "summary": summary,
        "aggregates": {
            "domains": sorted_domains,
            "resource_types": dict(resource_types.most_common()),
            "protocols": dict(protocols.most_common()),
            "statuses": dict(statuses.most_common()),
            "methods": dict(methods.most_common()),
            "mime_types": dict(mime_types.most_common(30)),
            "tracker_categories": dict(tracker_categories.most_common()),
            "tracker_rules": dict(tracker_rules.most_common()),
        },
        "requests": requests,
        "scores": {},
        "findings": [],
    }


def calculate_scores(report: Dict[str, Any]) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    scorecard = calculate_scorecard(report)
    insecure_items = [
        item
        for item in report["requests"]
        if item.get("scheme") == "http" and item.get("domain") not in ("localhost", "127.0.0.1", "::1")
    ]
    old_tls_items = [
        item
        for item in report["requests"]
        if str((item.get("security_details") or {}).get("protocol", "")).lower() in ("tls 1.0", "tls 1.1")
    ]
    scores = scorecard["scores"]
    findings = []
    if insecure_items:
        findings.append(
            finding(
                "critical",
                "security",
                "unencrypted-http",
                f"{len(insecure_items)} unencrypted HTTP requests",
                "Use HTTPS for every non-local resource.",
                [str(item.get("url") or "") for item in insecure_items[:10]],
                confidence="high",
                basis="observed",
            )
        )
    if old_tls_items:
        findings.append(
            finding(
                "critical",
                "security",
                "legacy-tls",
                f"{len(old_tls_items)} requests use legacy TLS",
                "Disable TLS 1.0/1.1 on the server.",
                [f"{(item.get('security_details') or {}).get('protocol')} {item.get('url', '')}" for item in old_tls_items[:10]],
                confidence="high",
                basis="observed",
            )
        )
    return scores, findings


def finding(
    severity: str,
    category: str,
    code: str,
    title: str,
    recommendation: str = "",
    evidence: Optional[List[str]] = None,
    confidence: str = "high",
    limitations: Optional[List[str]] = None,
    basis: str = "observed",
) -> Dict[str, Any]:
    evidence_values = [str(value) for value in (evidence or [])]
    return {
        "severity": severity,
        "category": category,
        "code": code,
        "title": title,
        "recommendation": recommendation,
        "evidence": evidence_values,
        "confidence": confidence,
        "basis": basis,
        "limitations": limitations or [],
        "evidence_details": [{"type": "observation", "value": value} for value in evidence_values],
    }


def generate_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    summary = report["summary"]
    requests = report["requests"]
    findings: List[Dict[str, Any]] = []
    errors = [item for item in requests if item.get("failed") or (item.get("status") or 0) >= 400]
    if errors:
        findings.append(
            finding(
                "warning",
                "reliability",
                "request-errors",
                f"{len(errors)} requests failed or returned HTTP errors",
                "Inspect the failed-request table and fix broken dependencies or blocked resources.",
                [item.get("url", "") for item in errors[:5]],
            )
        )
    slow = sorted((item for item in requests if (item.get("duration_ms") or 0) >= 1000), key=lambda item: item.get("duration_ms") or 0, reverse=True)
    if slow:
        findings.append(
            finding(
                "warning",
                "performance",
                "slow-requests",
                f"{len(slow)} requests take at least one second",
                "Reduce server latency, connection setup, or resource size; prioritize critical resources.",
                [f"{item.get('duration_ms')}ms {item.get('url')}" for item in slow[:5]],
            )
        )
    large = sorted((item for item in requests if (item.get("transfer_bytes") or 0) >= 1_000_000), key=lambda item: item.get("transfer_bytes") or 0, reverse=True)
    if large:
        findings.append(
            finding(
                "warning",
                "performance",
                "large-resources",
                f"{len(large)} resources exceed 1 MB",
                "Compress, resize, lazy-load, or split large assets.",
                [f"{item.get('transfer_bytes')} bytes {item.get('url')}" for item in large[:5]],
            )
        )
    if summary["duplicate_requests"]:
        duplicates = Counter(item.get("url", "") for item in requests)
        findings.append(
            finding(
                "info",
                "performance",
                "duplicate-requests",
                f"{summary['duplicate_requests']} duplicate network requests",
                "Deduplicate application fetches and verify caching headers.",
                [f"{count}× {url}" for url, count in duplicates.most_common(5) if count > 1],
            )
        )
    if summary["trackers"]:
        tracker_count = int(summary["trackers"])
        request_label = "request" if tracker_count == 1 else "requests"
        tracker_items = [item for item in requests if item.get("tracker_match")]
        tracker_evidence = []
        for item in tracker_items[:10]:
            match = item["tracker_match"]
            tracker_evidence.append(
                f"{item.get('domain', '')} — {match.get('rule_id')} ({match.get('category')}, {match.get('confidence')} confidence)"
            )
        findings.append(
            finding(
                "warning" if summary["trackers"] >= 3 else "info",
                "privacy",
                "tracking-requests",
                f"{tracker_count} {request_label} matched curated tracker signatures",
                "Review consent, necessity, retention, and third-party privacy terms.",
                tracker_evidence,
                confidence="medium",
                limitations=[
                    "Endpoint signatures do not prove user tracking, consent status, purpose, or legal compliance.",
                    "The bundled dataset is intentionally small and unmatched traffic may still contain analytics or tracking.",
                ],
                basis="heuristic",
            )
        )
    if summary["third_party_percent"] >= 50:
        third_party_domains = sorted(
            {
                str(item.get("registrable_domain") or item.get("domain") or "")
                for item in requests
                if item.get("third_party")
            }
        )
        inferred = any(item.get("third_party_confidence") == "low" for item in requests)
        findings.append(
            finding(
                "warning",
                "privacy",
                "third-party-heavy",
                f"{summary['third_party_percent']}% of requests are third-party",
                "Audit third-party dependencies and self-host critical assets where practical.",
                third_party_domains[:10],
                confidence="low" if inferred else "high",
                limitations=["The primary site was inferred from the first request."] if inferred else [],
                basis="derived",
            )
        )
    http1 = sum(count for protocol, count in report["aggregates"]["protocols"].items() if protocol.lower() in ("http/1.0", "http/1.1"))
    if http1 >= 5:
        findings.append(
            finding(
                "info",
                "performance",
                "http1-heavy",
                f"{http1} requests use HTTP/1.x",
                "Enable HTTP/2 or HTTP/3 where supported.",
                [f"Observed protocol counts: {report['aggregates']['protocols']}"],
            )
        )
    if summary["cache_percent"] < 10 and summary["requests"] >= 20:
        findings.append(
            finding(
                "info",
                "performance",
                "low-cache-hit",
                f"Only {summary['cache_percent']}% of requests were served from cache",
                "Review Cache-Control, ETag and immutable asset naming.",
                [f"{summary['cached']}/{summary['requests']} requests were marked as cache hits"],
                confidence="medium",
                limitations=["Cache metadata availability differs between recording sources."],
                basis="derived",
            )
        )
    if not findings:
        findings.append(
            finding(
                "ok",
                "overview",
                "clean-session",
                "No major issues detected by the enabled rules",
                evidence=[f"Evaluated {summary['requests']} requests"],
                confidence="medium",
                limitations=["A clean rule result does not prove that the session is private, secure, or error-free."],
                basis="heuristic",
            )
        )
    return findings


def sort_findings(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    return sorted(values, key=lambda item: (order.get(item.get("severity", "info"), 2), item.get("category", ""), item.get("code", "")))


def finalize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Attach scores plus additive evidence/assessment metadata."""

    report["scores"], initial = calculate_scores(report)
    context = build_assessment_context(report, report["scores"])
    report["facts"] = context["facts"]
    report["assessments"] = context["assessments"]
    report["analysis_metadata"] = {
        "methodology_version": context["methodology_version"],
        "datasets": context["datasets"],
        "score_compatibility": "Scores remain heuristic 0-100 values for existing consumers; assessments carry confidence and limitations.",
    }
    report["findings"] = sort_findings(initial + generate_findings(report))
    return report


def analyze_recording(path: str, show_sensitive: bool = False) -> Dict[str, Any]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(path)
    if source.suffix.lower() == ".har":
        raw = load_har(path, show_sensitive=show_sensitive)
        requests = normalize_har(raw)
        report = build_report(requests, "har", {"source": path, "har_summary": raw.get("summary", {})}, [])
        return finalize_report(report)
    events, parse_errors = read_jsonl(path)
    if any(item.get("type") == "cdp_event" for item in events):
        report = analyze_cdp_events(events, parse_errors=parse_errors)
        report["source_metadata"]["path"] = path
        return report
    proxy_events = [item for item in events if item.get("type") == "proxy_request"]
    if proxy_events:
        requests = []
        for index, event in enumerate(proxy_events):
            url = str(event.get("target", ""))
            domain = str(event.get("host") or urlsplit(url).hostname or "unknown")
            response = event.get("response", {}) if isinstance(event.get("response"), dict) else {}
            response_headers = response.get("headers", {}) if isinstance(response.get("headers"), dict) else {}
            requests.append(
                {
                    "id": f"proxy-{index}",
                    "redirect_index": 0,
                    "url": url,
                    "scheme": "https" if event.get("mode") == "tls_tunnel" else (urlsplit(url).scheme or "http"),
                    "domain": domain,
                    "path": urlsplit(url).path or "/",
                    "query_keys": [],
                    "method": event.get("method", "?"),
                    "resource_type": "tunnel" if event.get("mode") == "tls_tunnel" else "http",
                    "document_url": "",
                    "started_at": event.get("timestamp"),
                    "started_monotonic": None,
                    "started_wall_time": None,
                    "offset_ms": 0,
                    "duration_ms": event.get("duration_ms", 0),
                    "status": int(response.get("status", 0) or 0),
                    "status_text": response.get("reason", ""),
                    "protocol": response.get("http_version") or event.get("http_version", "unknown"),
                    "mime_type": str(response_headers.get("Content-Type") or response_headers.get("content-type") or "unknown").split(";", 1)[0],
                    "transfer_bytes": int(event.get("download_bytes", 0) or 0) + int(event.get("upload_bytes", 0) or 0),
                    "body_bytes": int(event.get("download_bytes", 0) or 0),
                    "failed": not event.get("ok", False),
                    "failure": event.get("error"),
                    "from_cache": False,
                    "third_party": False,
                    "tracker": is_tracker(url, domain),
                    "timing": {"ttfb_ms": event.get("ttfb_ms")},
                    "request_headers": event.get("headers", {}),
                    "response_headers": response_headers,
                    "remote_ip": None,
                    "remote_port": event.get("port"),
                    "security_details": None,
                }
            )
        normalize_requests(requests)
        report = build_report(requests, "proxy-jsonl", {"path": path}, parse_errors)
        return finalize_report(report)
    connection_events = [item for item in events if item.get("type") in ("connection_open", "connection_close")]
    if connection_events:
        processes = Counter(item.get("connection", {}).get("process", "unknown") for item in connection_events)
        return {
            "schema_version": 2,
            "generated_at": utc_now(),
            "source_type": "connection-jsonl",
            "source_metadata": {"path": path},
            "parse_errors": parse_errors,
            "summary": {
                "events": len(connection_events),
                "opened": sum(item.get("type") == "connection_open" for item in connection_events),
                "closed": sum(item.get("type") == "connection_close" for item in connection_events),
                "processes": len(processes),
            },
            "aggregates": {"processes": dict(processes.most_common())},
            "requests": [],
            "scores": {},
            "findings": [],
        }
    raise ValueError("recording contains no supported CDP, proxy, or connection events")


def compare_recordings(before_path: str, after_path: str) -> Dict[str, Any]:
    before = analyze_recording(before_path)
    after = analyze_recording(after_path)
    keys = (
        "requests",
        "domains",
        "transfer_bytes",
        "page_span_ms",
        "failed",
        "http_errors",
        "third_party",
        "trackers",
        "slow_requests",
        "large_requests",
    )
    deltas = {}
    for key in keys:
        old = before.get("summary", {}).get(key, 0) or 0
        new = after.get("summary", {}).get(key, 0) or 0
        deltas[key] = {
            "before": old,
            "after": new,
            "delta": round(new - old, 2),
            "percent": round((new - old) / old * 100, 1) if old else None,
        }
    score_deltas = {}
    for key in set(before.get("scores", {})) | set(after.get("scores", {})):
        old = before.get("scores", {}).get(key, 0)
        new = after.get("scores", {}).get(key, 0)
        score_deltas[key] = {"before": old, "after": new, "delta": new - old}
    return {
        "schema_version": 2,
        "generated_at": utc_now(),
        "before": before_path,
        "after": after_path,
        "deltas": deltas,
        "score_deltas": score_deltas,
    }


def export_requests_csv(report: Dict[str, Any], output: str) -> None:
    fields = [
        "started_at",
        "offset_ms",
        "method",
        "status",
        "protocol",
        "resource_type",
        "mime_type",
        "duration_ms",
        "transfer_bytes",
        "body_bytes",
        "domain",
        "remote_ip",
        "from_cache",
        "third_party",
        "tracker",
        "failed",
        "url",
    ]
    with atomic_text_writer(output, newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report.get("requests", []))


def export_har(report: Dict[str, Any], output: str) -> None:
    entries = []
    for item in report.get("requests", []):
        timing = item.get("timing") or {}
        duration = float(item.get("duration_ms", 0) or 0)
        known = [
            value
            for value in (
                timing.get("queueing_ms"),
                timing.get("dns_ms"),
                timing.get("connect_ms"),
                timing.get("ssl_ms"),
                timing.get("send_ms"),
                timing.get("ttfb_ms"),
            )
            if isinstance(value, (int, float)) and value >= 0
        ]
        receive = max(0.0, duration - sum(known))
        started = item.get("started_at") or report.get("generated_at") or utc_now()
        request_headers = item.get("request_headers") if isinstance(item.get("request_headers"), dict) else {}
        response_headers = item.get("response_headers") if isinstance(item.get("response_headers"), dict) else {}
        entries.append(
            {
                "startedDateTime": started,
                "time": duration,
                "request": {
                    "method": item.get("method", "GET"),
                    "url": item.get("url", ""),
                    "httpVersion": item.get("protocol", ""),
                    "cookies": [],
                    "headers": [{"name": key, "value": str(value)} for key, value in request_headers.items()],
                    "queryString": [{"name": key, "value": "[not retained]"} for key in item.get("query_keys", [])],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": int(item.get("status", 0) or 0),
                    "statusText": item.get("status_text", ""),
                    "httpVersion": item.get("protocol", ""),
                    "cookies": [],
                    "headers": [{"name": key, "value": str(value)} for key, value in response_headers.items()],
                    "content": {"size": int(item.get("body_bytes", 0) or 0), "mimeType": item.get("mime_type", "unknown")},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": int(item.get("transfer_bytes", 0) or 0),
                },
                "cache": {"comment": "served from cache"} if item.get("from_cache") else {},
                "timings": {
                    "blocked": timing.get("queueing_ms", -1) if timing.get("queueing_ms") is not None else -1,
                    "dns": timing.get("dns_ms", -1) if timing.get("dns_ms") is not None else -1,
                    "connect": timing.get("connect_ms", -1) if timing.get("connect_ms") is not None else -1,
                    "ssl": timing.get("ssl_ms", -1) if timing.get("ssl_ms") is not None else -1,
                    "send": timing.get("send_ms", 0) if timing.get("send_ms") is not None else 0,
                    "wait": timing.get("ttfb_ms", 0) if timing.get("ttfb_ms") is not None else 0,
                    "receive": round(receive, 2),
                },
                "serverIPAddress": item.get("remote_ip"),
                "connection": str(item.get("connection_id") or ""),
                "comment": item.get("failure") or "",
            }
        )
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "WireScope", "version": "0.2"},
            "comment": "Generated from a WireScope normalized recording. Redacted fields cannot be reconstructed.",
            "entries": entries,
        }
    }
    atomic_write_text(output, json.dumps(har, ensure_ascii=False, indent=2))
