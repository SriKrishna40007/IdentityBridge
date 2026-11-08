# Architecture

```text
Browser/API client
      |
      v
FastAPI application ---- OIDC ---- Keycloak
      |                         (identity and roles)
      |
      +---- Authorization: current application-client roles
      |
      +---- JIT request/decision/grant/revoke services
      |                 |
      +---- Audit writer|
      |                 v
      +-------------- PostgreSQL
      |
      +---- Optional expiry worker ---- Keycloak Admin API
```

## Components
- Keycloak handles OIDC authentication and stores identities/client roles.
- FastAPI exposes authentication, user administration, access and JIT endpoints.
- PostgreSQL stores application/JIT/audit data.
- SQLAlchemy and Alembic provide persistence and migrations.
- Security middleware includes request IDs, origin validation, CSRF, rate limiting, security headers and sessions.

## JIT lifecycle
Request creation serializes competing requests for the same target/role using a PostgreSQL advisory transaction lock. Decisions lock the request row, reject self-approval and accept decisions only while pending. Audit writes are transactionally coupled where implemented.

The grant/revoke lifecycle tracks whether a role is JIT-owned. Revocation is restricted to verified JIT-owned roles. Stale `revoke_pending` claims can be reclaimed after the five-minute lease.

## Operational boundary
The worker starts only when `jit_worker_enabled` is true; default is false. The current approval route uses `exclusive_role_writer=False`, so absent-role assignment is not assumed safe. This is application-level JIT/PIM-style functionality, not Microsoft Entra PIM. Production use requires deployment-specific hardening and operational review.
