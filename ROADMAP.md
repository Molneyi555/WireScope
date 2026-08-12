# WireScope roadmap

WireScope is building a macOS-first workflow that can **record, correlate, and explain** network activity without requiring an account or sending captures to a hosted service.

This roadmap communicates priorities, not dates or promises. Released behavior is documented in [CHANGELOG.md](CHANGELOG.md); proposed work belongs in issues before implementation.

## Product principles

- Local and redacted by default.
- Evidence and visibility limits accompany every conclusion.
- One coherent session is more valuable than another disconnected command.
- Beginner-friendly explanations and expert-level artifacts coexist.
- Privileges are narrow, explicit, optional, and auditable.
- macOS quality comes before cross-platform breadth.

## Release candidate 0.3.0 — trustworthy local core

The implementation is feature-frozen while compatibility, packaging, benchmarks, and release artifacts are validated. It becomes a shipped release only after a clean `v0.3.0` tag and verified GitHub/PyPI artifacts exist.

- Private-from-creation, symlink-safe, atomic artifact output across recordings, captures, exports, reports, and dashboard snapshots.
- Structured macOS command/capability diagnostics, explicit exit-code policy, parser metadata, and real-output fixtures.
- Strict CDP/WebSocket protocol and memory limits plus a configurable, defense-in-depth share-safe export policy.
- A versioned event envelope, EventBus, SQLite session store, explicit user markers, and JSONL import.
- A unified live Timeline and durable session report with typed events, entities, relations, findings, confidence, and evidence.
- Initial process → connection → endpoint and browser request → domain/IP/TLS correlation.
- Hash-addressed HAR/JSONL ingest, schema migration by verified copy, and non-mutating session integrity checks.
- Bounded `who`, `what`, and `why` evidence queries plus versioned data-only rule packs.
- Statistical `.wsbaseline` comparisons with explicit regression, unknown, and incompatible states.
- Human-approved Network Manifests for domains, protocols, TLS, routes, resolvers, tunnels, findings, baselines, and budgets.
- Session tags, verified merge with clock offsets, evidence-aware pruning, share-safe export, and fixed-contract support bundles.
- Full offline Public Suffix List semantics, structured tracker matching, auditable score factors, and assessment limitations.
- Reusable CI budgets, standard source/wheel packaging, release benchmarks, expanded CI/security automation, and fresh-install smoke tests.

## Next — deeper correlation and explanation

- Link DNS answers, sockets, routes, interfaces, tunnels, browser requests, and TLS observations across sensors using bounded time windows and explicit confidence.
- Expand deterministic rules for tunnel bypass risk, unexpected listeners, resolver degradation, TLS/QUIC fallback, and cross-sensor timing chains.
- Add a bounded entity query/filter language and multi-selection graph explanations on top of `who/what/why`.
- Add automated retention policies, attachment references, crash recovery journals, and opt-in forensic hash chains.
- Extend baselines to longitudinal cohorts and compare complete session topology, DNS, route, TLS, and finding deltas.
- Add reviewed Manifest templates and clearer remediation for required evidence that a selected sensor cannot observe.
- Extend fixture coverage across more macOS releases, locales, permission states, and interrupted recordings.

## Later — richer local experience

- Add optional local visualization of the entity graph and correlated waterfall/timeline selections.
- Evaluate plugin-style importers and curated community rule packs on the existing versioned data-only contract.
- Improve onboarding and remediation guidance without hiding sensor visibility boundaries.

## Native experience — only after contracts stabilize

- Evaluate a narrowly scoped Rust helper for higher-fidelity event collection.
- Authenticate local clients and keep the privileged protocol small and versioned.
- Add a thin menu-bar companion for status, recording, onboarding, and local alerts.
- Publish signed/notarized artifacts only after the full release and security process exists.

## Explicit non-goals before 1.0

- Linux or Windows parity.
- A custom TLS interception stack or silent certificate-authority installation.
- Active LAN exploitation or stealth scanning.
- Required accounts, cloud storage, or behavioral telemetry.
- Claims that metadata alone proves malicious intent.

## Contributing to the roadmap

Start with a problem statement and a reproducible user workflow in a [feature request](https://github.com/Molneyi555/WireScope/issues/new/choose). Changes that improve fixtures, privacy guarantees, explainability, documentation, or failure messages are especially valuable early contributions.
