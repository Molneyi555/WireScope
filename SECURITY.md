# Security and privacy

## Supported versions

During alpha, security fixes target the latest tagged release and the `main` branch. Older snapshots may receive no backports. Release notes will call out any security-relevant migration or artifact invalidation.

## Reporting a vulnerability

Do not open a public issue containing credentials, private recordings, exploit details, or personal network data. Contact the maintainers through the repository's [private security advisory form](https://github.com/Molneyi555/WireScope/security/advisories/new).

Include the affected version, operating system, reproduction steps, impact, and a minimal synthetic fixture when possible.

## Threat model

WireScope processes highly sensitive local metadata. URLs, DNS names, process names, headers, bodies, cookies, and PCAPs may reveal credentials or personal activity.

Defenses in the default configuration:

- no WireScope telemetry or cloud upload;
- authorization, cookies, tokens, credentials, bodies, WebSocket payloads, and sensitive query parameters are redacted;
- proxy binds to loopback and refuses remote binds without explicit acknowledgement;
- HTTPS proxy traffic remains opaque CONNECT tunnels;
- body collection is opt-in and size-limited;
- browser recording uses an isolated profile when WireScope launches Chrome;
- generated artifacts are owner-only (`0600`) from creation, refuse final-path symlinks, and use atomic replacement for one-shot exports;
- SQLite identity/schema, sidecars, inode stability, input sizes, stored JSON, migration snapshots, and evidence traversals are validated before trust or mutation;
- share-safe session exports and support bundles are the default; raw `.wsdb` inclusion requires an explicit private opt-in;
- support-bundle verification enforces a fixed manifest, payload hashes, sharing-mode agreement, safe regular ZIP entries, and aggregate/compression limits;
- system commands receive validated argument arrays rather than shell strings.

## User responsibilities

- Capture only devices and networks you own or are authorized to diagnose.
- Protect recordings as sensitive data.
- Avoid `--show-sensitive` unless necessary.
- Do not run the entire tool as root when only one capture command needs privileges.
- Review HTML/JSON/PCAP files before sharing them.
- Do not interpret a passing support-bundle verifier as permission to publish it; visible domains and findings can still identify activity.

## Known boundaries

- Redaction is defense-in-depth, not a guarantee that arbitrary application payloads contain no secrets.
- Reverse DNS and tracker classification are heuristic.
- Route-level VPN checks cannot prove external egress without contacting an external endpoint.
- A compromised local administrator can observe or modify the same traffic WireScope sees.
