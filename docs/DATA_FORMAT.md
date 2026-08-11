# Data formats

## JSONL recordings

Each line is one JSON object. Files begin with `session_start`, contain typed events, and end with `session_end` when collection completes normally.

Common types:

- `cdp_event` — raw redacted Chrome DevTools event;
- `cdp_command_result` — result of commands such as `Performance.getMetrics`;
- `response_body` — body metadata and optional content;
- `proxy_request` — one HTTP request or CONNECT tunnel;
- `connection_open` / `connection_close` — system socket lifecycle;
- `dns_packet` — parsed plaintext DNS packet.

JSONL remains streamable even for very large sessions.

## Normalized analysis

`analyze` and `export --format json` produce `schema_version: 2` with:

- `summary` — session totals;
- `aggregates` — domains, protocols, statuses, methods, resource and MIME types;
- `scores` — overall, performance, reliability, privacy, and security;
- `findings` — severity, category, code, recommendation, and evidence;
- `requests` — normalized correlated requests;
- `browser` — lifecycle, WebSocket, and Performance metrics when available.

Unknown future fields should be ignored by consumers.

## Redaction

Redaction happens before CDP events are written. Information replaced with `[REDACTED]` cannot be reconstructed by later HAR/CSV exports.

## HAR

WireScope imports HAR 1.2 and exports normalized sessions back to HAR 1.2. CDP-only fields remain in JSON analysis because HAR cannot represent every browser event.

