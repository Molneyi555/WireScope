# Security Hardening Review: WireScope

## Evidence Basis

I inspected the repository at revision `03af0533fc3b8c20241618460ef566c3b6f2088c`, focusing on the threat model and every direct artifact-writing path. The evidence collection is recorded in [context.md](context.md). This is a source-derived design review, not a claim that a vulnerability has been exploited or fixed.

## Constraints

We assume a balanced change profile: preserve the dependency-free CLI, avoid changing output formats, and keep normal recording performance effectively unchanged. No explicit compatibility, latency, or memory budget was supplied.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Own the private-artifact boundary | Sensitive-artifact threat model and six dispersed write paths (`E001`–`E003`) | 1. Local file-mode guards; 2. Central secure-artifact API | Option 2, introduced incrementally | [Private artifact boundary](proposals/private-artifact-boundary.md) |

## Recommendation Summary

The immediate risk reduction is simple: every WireScope artifact should be private to its owner from the instant it is created. The more durable improvement is to make that property belong to one API instead of every recorder. I recommend Option 2 because it prevents future writers from silently inheriting a permissive `umask`, while preserving existing formats and command behavior. A small tactical patch from Option 1 remains useful during migration.

Proxy authentication, destination allowlists, and connection quotas are deferred. They may matter for deliberately remote proxy deployments, but the current evidence does not establish that such deployments are common enough to justify mixing that larger policy decision into this change.

## Next Decisions

Select Option 1 for the smallest patch, or Option 2 for the recommended owned boundary. After selection, the implementation plan should pin the current revision, add mode/symlink regression tests, and update `SECURITY.md` with the resulting guarantee.
