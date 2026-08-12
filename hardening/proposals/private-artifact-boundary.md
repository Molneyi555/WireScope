# Security Hardening Proposal: Own the Private Artifact Boundary

## Decision

We need to decide whether private file creation remains a convention repeated by each recorder or becomes an invariant owned by one artifact-writing boundary.

## Executive Recommendation

The complete choice is:

- **Option 1: Local file-mode guards** adds explicit owner-only modes at every current write site.
- **Option 2: Central secure-artifact API** moves creation, replacement, and post-create verification behind one small module, while adapting external writers such as `tcpdump`.

I recommend Option 2 under the current balanced constraints, introduced with the tactical protections from Option 1. It has slightly more migration work, but it matches the repository's existing privacy promise: sensitive output should be safe by construction, not safe only when the caller's shell happens to use a restrictive `umask`.

## Evidence

I inspected the threat model and the direct file writers. The evidence that most influenced the diagnosis was not a single dangerous line; it was the repeated ownership pattern across otherwise unrelated sensors.

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `E001` | Sensitive local artifact threat model | `SECURITY.md` says URLs, process names, headers, bodies, cookies, and PCAPs may expose credentials or personal activity. |
| `E002` | Dispersed artifact creation | `wirescope/record.py:31`, `wirescope/cdp.py:223`, `wirescope/capture.py:86`, `wirescope/proxy.py:53`, `wirescope/report.py:231`, and `wirescope/tui.py:207` create files independently. |
| `E003` | Explicit raw-data modes | `wirescope/proxy.py:183-188` and the CDP recorder can persist bodies or unredacted data when the user opts in. |

Observed: these paths use ordinary `Path.open`, `Path.write_text`, or an external `tcpdump -w` operation, and no shared layer asserts owner-only permissions. Inferred: file confidentiality is currently delegated to process `umask` and caller discipline. That is a structural mismatch with a tool whose core output is explicitly classified as sensitive.

## Current Design And Failure Mode

Each sensor owns both data collection and filesystem creation. This keeps modules simple, but it duplicates a security decision that is easy to omit. On a system or launch environment with a permissive `umask`, a newly created recording may be readable by users outside the intended owner. Existing files are another concern: opening with `"w"` or `"a"` follows the normal filesystem path-resolution rules, so the call site has no common policy for symlinks, ownership, or replacement.

We should distinguish this from redaction. Redaction reduces the amount of sensitive material in default output; it does not make process lists, DNS names, remote endpoints, timing, or opt-in raw bodies non-sensitive. The failure boundary is therefore the file itself.

## Desired Invariants

- Every WireScope-created artifact is accessible only to its owner from initial creation onward.
- A sensitive writer does not follow an unexpected symlink at the final output path.
- Replacement does not expose a partially written file when atomic output is practical.
- External writers are verified or constrained so they cannot bypass the file policy silently.
- Existing output formats, paths, and dependency-free operation remain compatible.

## Constraints And Non-Goals

We preserve current CLI syntax and file formats. This proposal does not encrypt recordings at rest, manage keys, prevent an administrator from reading them, or decide whether remote proxy operation should require authentication. It also does not claim that redaction catches secrets embedded in arbitrary payloads.

## Before Architecture

[Before diagram](../diagrams/private-artifact-boundary-before.mmd)

The current diagram shows the important ownership issue: collectors flow directly into multiple filesystem primitives, and the effective access control comes from ambient process state. A future exporter can easily repeat the pattern without noticing that it has inherited a security obligation.

## Options

### Option 1: Local File-Mode Guards

This option preserves the current module boundaries. Each direct writer creates its destination with owner-only permissions, and the `tcpdump` path is checked or corrected after creation. Existing output code remains recognizable, review scope is small, and rollback is a focused revert.

Its strongest case is speed and low compatibility risk. There is no new abstraction and no meaningful performance or memory mechanism beyond a small number of mode-related system calls. It directly addresses currently known paths. The residual risk is recurrence: every new export feature must remember the rule, and subtle concerns such as symlink refusal and atomic replacement are likely to remain uneven.

[Option 1 diagram](../diagrams/private-artifact-boundary-local-modes-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| File mode | Inherited from `umask` | Explicit `0600` per writer | Narrows local disclosure | Small edits at each site |
| Policy owner | Each caller implicitly | Each caller explicitly | Current paths improve; drift remains | Repeated review burden |
| External output | `tcpdump` owns creation | Mode verified/corrected | PCAP follows the same confidentiality goal | Extra post-create check |

The key improvement is concrete but narrow: the known files become private. I would choose this option if a minimal patch must ship immediately and the team accepts a follow-up architectural change.

### Option 2: Central Secure-Artifact API

This option adds a small internal module that owns private creation, text/binary streaming, and atomic text replacement. Callers request an artifact handle rather than choosing raw open flags. The API refuses unexpected symlinks at the destination, uses owner-only modes at creation, and verifies the final file. External tools receive a prepared or verified path through a dedicated adapter.

The attractive part is future safety: a new recorder gets the privacy invariant by using the normal project API. Security review becomes concentrated around one boundary, and tests can exercise file mode, symlink behavior, overwrite semantics, and error cleanup once. No process or service boundary is introduced, so runtime overhead is limited to filesystem metadata operations during open/close rather than per event.

What gives me pause is migration detail. `tcpdump` has its own creation semantics, append-mode proxy logs have different atomicity needs from one-shot reports, and changing overwrite behavior could surprise scripts. We should migrate by writer class, preserve tactical `0600` checks throughout, and make rollback possible at each call site.

[Option 2 diagram](../diagrams/private-artifact-boundary-secure-api-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Policy owner | Six or more writers | One secure-artifact module | Reduces omission and drift | New internal API |
| Symlink behavior | Ambient filesystem behavior | Explicit refusal policy | Narrows path-substitution risk | Compatibility test needed |
| One-shot reports | Direct overwrite | Private temporary + atomic replace | Avoids partial exposure | One rename and temporary file |
| Streaming logs | Direct open | Private streaming handle | Private from first byte | Small open/close metadata cost |
| External writer | Unowned exception | Dedicated verified adapter | Makes bypass visible and testable | Platform-specific validation |

The important edge in this design is ownership, not code reuse. Once the sink enforces the invariant, a caller cannot accidentally select a weaker mode. We still retain redaction and user warnings because local file permissions do not protect a deliberately shared artifact or a compromised owner account.

## Comparison

| Dimension | Option 1: Local guards | Option 2: Secure API |
| --- | --- | --- |
| Security | Improves known paths; future drift remains | Improves known paths and recurrence resistance |
| Performance | Neutral; mode syscall per file | Neutral in event loop; extra metadata/rename per artifact |
| Memory | Neutral | Neutral; bounded path/temporary state |
| Reliability | Low behavioral change | Atomic one-shot writes improve partial-file behavior; migration can introduce edge cases |
| Operability | Repeated audits of writers | One boundary and one test suite to audit |
| Migration | Small, dispersed patch | Moderate, incremental caller migration |
| Rollback | Revert individual mode edits | Keep adapter per caller and revert migrations independently |

Neither option needs a fabricated performance score. The relevant workload is artifact open/close, not event throughput. Validation should compare recording throughput and generated bytes on representative sessions and confirm that any difference is below normal run-to-run noise.

## Recommendation

I recommend Option 2 with an incremental rollout. It gives the privacy promise a clear owner without adding dependencies, processes, or format changes. Option 1 becomes preferable if compatibility with symlinked destinations is an intentional supported behavior or if the immediate change budget cannot accommodate migration tests; in that case, we should still record centralization as follow-up work.

## Evidence Coverage And Residual Risk

| Evidence | Option 1 | Option 2 | Tactical fix still required? |
| --- | --- | --- | --- |
| `E001` — Sensitive artifact threat model | Mitigates local disclosure | Mitigates local disclosure and control drift | Yes, documentation and sharing warnings remain |
| `E002` — Dispersed artifact creation | Addresses current sites | Addresses current sites and consolidates ownership | Yes during migration |
| `E003` — Explicit raw-data modes | Mitigates file exposure | Mitigates file exposure with one invariant | Yes, explicit opt-in remains necessary |

Residual risks include intentional sharing, backup/indexing software running as the owner, administrator access, sensitive data written to stdout, and arbitrary secrets that redaction cannot recognize. Encryption at rest would address a different threat model and is not implied by either option.

## Migration And Rollout

First add regression tests that run under a permissive `umask` and assert owner-only files. Then protect current writers tactically. For Option 2, migrate one-shot JSON/HTML writers, streaming JSONL writers, and finally external PCAP output as separate reviewable changes. Preserve paths and formats, and retain the old helper per caller until its replacement tests pass. Roll back by reverting a caller to its protected local writer rather than removing the central module wholesale.

## Validation Plan

- Create each artifact type under `umask 000` and assert mode `0600`.
- Attempt output through a final-component symlink and verify the selected policy.
- Interrupt one-shot report generation and verify no partially replaced destination.
- Exercise overwrite and append behavior expected by existing CLI commands.
- Run the existing 21-test suite plus new artifact tests on macOS.
- Compare representative event throughput and output size before and after; investigate any repeatable regression above test noise.

## Implementation Work Packages

- Define the secure-artifact API and its symlink, overwrite, and append contracts.
- Add mode and path-substitution tests before migrating callers.
- Apply tactical private-mode protections to all current writers.
- Migrate one-shot, streaming, and external-tool outputs in separate commits.
- Update `SECURITY.md`, architecture documentation, and release notes.

## Open Questions

- Are symlinked output destinations intentionally supported today?
- Should reports that are explicitly prepared for sharing have a separate export command or permission override?
- Must proxy JSONL append to an existing file owned by the user, or can each run require a new private file?
