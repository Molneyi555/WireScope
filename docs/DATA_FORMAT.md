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

## SQLite session databases (`.wsdb`)

`session record` and a `.wsdb` output from `record` create a portable SQLite database. Current session schema version `2` is independent from JSON analysis and event-envelope versions. The database currently contains:

- `schema_info` — independent component versions for session and event contracts;
- `sessions` — recording lifecycle, source, WireScope version, host/config context, and collector summary;
- `metadata` — store-level values such as the active session ID;
- `artifacts` — ingested-source provenance with SHA-256, byte size, source path/type, import time, and metadata;
- `events` — ordered event envelopes with source, type, severity, confidence, entity/correlation/artifact IDs, source index, original timestamp, and JSON payload;
- `entities` — stable typed identities, labels, attributes, and first/last observed timestamps;
- `relations` — directional typed edges with confidence, rule/version/basis metadata, and JSON evidence;
- `findings` — rule-pack metadata, category, severity, confidence, explanation, recommendation, evidence, limitations, and status.

Event envelopes use `schema_version: 2` and the logical fields `event_type`, `source`, `payload`, `timestamp`, `severity`, `confidence`, `entity_id`, `correlation_id`, `artifact_id`, `source_index`, and `original_timestamp`. The SQLite `sequence` is the canonical ordering within a file; `timestamp` is normalized to UTC while `original_timestamp` preserves the source representation when available.

Current system sessions use event types such as `connection.opened`, `connection.closed`, `network.routes.snapshot`, `network.routes.changed`, `network.dns.*`, `network.vpn.*`, `network.proxy.*`, `session.started`, `session.finished`, and `user.marker`. Imported browser events use `browser.<CDP method>`. Readers must preserve or ignore unknown future types rather than assuming this list is exhaustive.

Entity IDs are deterministic hashes of the entity type and natural key. Relations distinguish directly observed links from weaker inference through `confidence` and `evidence`; consumers must not treat an absent confidence value as certainty.

WireScope creates the database, WAL, shared-memory, and journal artifacts owner-only (`0600`) and refuses final-component symlinks and non-regular destinations. The database uses WAL while recording and is checkpointed on clean close. Copy the main file only after the recorder exits.

`session ingest` adds HAR or JSONL evidence to an existing schema-v2 database. Each source is hashed before parsing and rechecked before commit; the complete source import is one transaction, so a changed source or unexpected ingest failure leaves no partial events, entities, or provenance row. Malformed JSONL records are deliberately counted and skipped. A session cannot ingest itself, and a repeated source hash is rejected unless `--allow-duplicate` is explicit.

`session verify` opens a database read-only and checks its WireScope identity/schema, SQLite integrity, foreign keys, relation endpoints, evidence event references, and owner-only permissions without repairing it. `session migrate` uses SQLite backup into a private temporary file, applies supported forward migrations, validates the result, and atomically publishes a separate destination; it never upgrades the source in place. Schema v1 remains readable and can be copied forward to v2.

JSONL import is additive: malformed lines are counted and skipped, unknown object events are retained, and supported socket/CDP events receive entities and relations. It never rewrites the source recording.

### Session derivatives and support bundles

`session export` writes `wirescope-session-export` schema version `1` as JSON, one-event-per-line JSONL, or self-contained HTML. Export is strict share-safe by default; `--private` is an explicit opt-in. Share-safe JSON/HTML contains the `sharing_safety` manifest described below.

`session merge` always creates a new schema-v2 database. Source hashes, optional clock offsets, and deterministic ordering metadata are recorded; duplicate artifacts and identity collisions are rejected. Sources are reopened and rechecked before the verified destination is atomically published. `session prune` is a dry-run unless `--apply` is supplied and preserves user markers plus events referenced by relation/finding evidence.

A support bundle is a deterministic ZIP with `manifest.json`, `session.json`, `report.html`, `capability.json`, `redaction-policy.json`, and `REVIEW.md`. Share-safe bundles omit the raw database. A private bundle adds `raw/session.wsdb` only after `--include-raw-private`. Every manifest payload has a byte count and SHA-256; verification also enforces owner-only mode, fixed file sets, regular safe entry names, size/compression limits, sharing-mode consistency, and ZIP integrity. Verification never makes a bundle safe to publish without human review.

## Normalized analysis

`analyze` and `export --format json` produce `schema_version: 2` with:

- `summary` — session totals;
- `aggregates` — domains, protocols, statuses, methods, resource and MIME types;
- `scores` — overall, performance, reliability, privacy, and security;
- `facts` — directly counted observations used by assessments;
- `assessments` — per-category confidence, limitations, evidence, and auditable score factors;
- `findings` — severity, category, code, recommendation, structured evidence, confidence, and limitations;
- `requests` — normalized correlated requests;
- `browser` — lifecycle, WebSocket, and Performance metrics when available.

Requests retain backward-compatible `third_party` and `tracker` booleans while adding `registrable_domain`, the primary-party comparison basis, and a structured `tracker_match` when a versioned local classifier rule matched.

Unknown future fields should be ignored by consumers.

## Deterministic rule packs and findings

Rule packs use `schema_version: 1` and contain a pack ID/version, minimum WireScope version, and bounded data-only rules. Each rule declares its ID, title, category, severity, confidence, predicate, evidence selector, limitations, explanation, and remediation. Supported predicates operate on explicitly bounded event/entity/relation/finding/session data; executable fields, unknown operators, remote includes, duplicate JSON keys, and oversized packs are rejected.

`session analyze` stores idempotent findings with the pack ID/version and evidence references. `session why` resolves those references back to the events/entities that supported the conclusion. Severity and confidence are separate properties. A missing or ambiguous observation evaluates as unknown rather than silently satisfying a rule.

## Statistical baselines (`.wsbaseline`)

Baseline schema version `1` stores source fingerprints, capability and rule-pack compatibility, robust per-metric statistics (median, p90, median absolute deviation, missing counts), stable/observed sets, and optional absolute budgets. Statistical mode requires at least three sessions. Single-run mode requires explicit absolute limits and is not represented as a statistical baseline.

Comparison schema version `1` reports `pass`, `regression`, `unknown`, or `incompatible`. Missing metrics, changed capability profiles, and incompatible rule-pack context never become false passes. Set changes such as new domains are reported separately from policy violations. `baseline check` uses exit `0` for pass, `1` for regression, and `2` for unknown/incompatible or invalid input.

## Network Manifests

A `wirescope-network-manifest` schema version `1` has named profiles for allowed/denied domains, registrable domains, protocols, ports, TLS minimums, resolvers, routes, interfaces, tunnel requirements, tracker/rule IDs, budgets, findings, and an optional local baseline.

`manifest discover` writes an unapproved `proposal`; generated data cannot approve itself. Enforcement requires a human-reviewed `policy` with `approved: true` and an explicit profile name. Unknown fields, remote references, invalid patterns, and duplicate JSON keys are rejected. Every check is `pass`, `violation`, or `unevaluable`; unavailable required evidence fails the policy, while explicitly optional checks become warnings. Results can be human-readable, JSON, or private JUnit XML.

## Budget results

`budget --json` and `budget --output` produce `schema_version: 1` with:

- `passed` and `checked` — the overall result and number of evaluated limits;
- `budgets` and `metrics` — the normalized limits and observed values;
- `checks` — every comparison with its operator, limit, actual value, overage, and pass state;
- `violations` — the failing subset of `checks`;
- `source` and `policy_source` — the checked recording and optional reusable policy path.

Budget result schema versions are independent from normalized-analysis schema versions.

## Redaction

Redaction happens before CDP events are written. Information replaced with `[REDACTED]` cannot be reconstructed by later HAR/CSV exports.

Strict share-safe JSON and HTML exports add a `sharing_safety` object with `schema_version`, `mode`, effective redaction categories, remaining visible evidence, limitations, and the requirement for human review. Share-safe sanitization is a non-mutating second pass: it removes bodies, header/query values, URL paths/fragments, common identifiers, local paths, recognized credential formats, and bounded high-entropy candidates. Domain names and network findings remain visible intentionally.

Custom key, header, and dotted object/URL path globs are additive. Consumers must not infer that an artifact without `sharing_safety.mode == "share-safe"` was prepared for publication.

## HAR

WireScope imports HAR 1.2 and exports normalized sessions back to HAR 1.2. CDP-only fields remain in JSON analysis because HAR cannot represent every browser event.
