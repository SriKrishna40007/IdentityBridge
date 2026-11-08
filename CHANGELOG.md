# Changelog

## Unreleased — JIT privileged access

### Added
- JIT privileged-access request, approval and rejection API.
- Supported roles: `identity-admin`, `security-analyst`, `auditor`.
- Bounded duration (1–480 minutes; default 60) and decision comments.
- PostgreSQL concurrency/lifecycle handling and audit events.
- Ownership-aware expiry/revocation worker, retry and stale-claim recovery.
- JIT API, lifecycle, grant, worker, authorization and PostgreSQL atomicity tests.

### Security
- Self-approval and direct privileged-role assignment/removal blocked.
- Pre-existing roles are not JIT-owned.
- Unknown ownership requires manual reconciliation.
- Worker disabled by default.
- `exclusive_role_writer=False`; absent-role assignment is not assumed safe.

### Validation
- Full PostgreSQL-backed suite: 160 passed.
- PostgreSQL lifecycle atomicity: 2 passed.
- Ruff and compileall passed; four deprecation warnings remain.
