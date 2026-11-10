# IdentityBridge

IdentityBridge is an identity and access management security platform built with FastAPI, Keycloak and PostgreSQL. It provides OIDC sign-in, role-based access control (RBAC), identity administration, audit events and an application-level just-in-time (JIT) privileged-access workflow.

## What it does

Users authenticate through Keycloak. IdentityBridge checks application-client roles before allowing protected operations. Users can request supported privileged roles for themselves; an `identity-admin` can approve or reject the request.

Supported privileged roles: `identity-admin`, `security-analyst`, `auditor`. `standard-user` is managed through the ordinary user-role endpoints. Privileged roles cannot be directly assigned or removed through those endpoints.

## Architecture

- Keycloak: identity provider, OIDC authentication and client roles.
- FastAPI: API, sessions, authorization and lifecycle services.
- PostgreSQL: application persistence, JIT requests and audit records.
- Expiry worker: processes eligible expirations only when explicitly enabled.

This is an application-level JIT/PIM-style workflow, not Microsoft Entra PIM or Conditional Access.

## Quick start

Requirements: Python 3.12+, Docker Desktop, `uv`, and Git Bash or a compatible shell.

1. `cp .env.example .env`
2. Replace every placeholder in `.env` with strong local secrets. Never commit or share `.env`.
3. Start services: `docker compose up -d`
4. Create `identitybridge_app` if it does not already exist. Do not drop the Keycloak database or persistent volume.
5. Configure the `identitybridge` Keycloak realm, the `identitybridge-api` OIDC client and the dedicated `identitybridge-admin-service` client.
6. Install dependencies: `uv sync --all-groups`
7. Apply migrations: `uv run alembic upgrade head`
8. Start API: `uv run uvicorn identitybridge.main:app --host 127.0.0.1 --port 8000`

See [development setup](docs/development/setup.md) for complete configuration.

## JIT workflow

1. User submits a request for their own Keycloak subject, with a justification and duration.
2. An `identity-admin` reviews the pending request.
3. The administrator approves or rejects it. Self-approval is prohibited.
4. Approval invokes the role grant workflow and records lifecycle/audit state.
5. Expiry processing can revoke only roles proven to be JIT-granted.

Important current safety behaviour: the approval route passes `exclusive_role_writer=False`. An absent role is not blindly assigned; manual reconciliation may be required. Existing roles are treated as pre-existing and must not be automatically removed as JIT-owned. The expiry worker is disabled by default.

## API overview

Interactive API docs: `http://localhost:8000/docs`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health/live` | Liveness |
| GET | `/auth/login` | Start OIDC login |
| GET | `/auth/callback` | OIDC callback |
| GET | `/auth/me` | Current session |
| POST | `/auth/logout` | Clear session |
| POST | `/api/v1/privileges/requests` | Submit own JIT request |
| GET | `/api/v1/privileges/requests` | List own requests |
| GET | `/api/v1/privileges/pending` | List pending requests |
| POST | `/api/v1/privileges/{request_id}/approve` | Approve request |
| POST | `/api/v1/privileges/{request_id}/reject` | Reject request |

User administration endpoints are under `/api/v1/admin/users`; example protected resources are under `/api/v1/access`.

## Latest recorded validation

- Added OIDC step-up authentication requiring ACR 2 and authentication freshness within 300 seconds for privileged approval.
- Privilege approval requires both the `identity-admin` role and recent step-up authentication.


- Full test suite: **197 passed, 2 skipped**; PostgreSQL integration separately: **2 passed**.
- PostgreSQL lifecycle atomicity tests: **2 passed**.
- Ruff: passed; `git diff --check`: passed.
- Ruff: passed.
- Four deprecation warnings were reported, without test failures.
- Manual browser OIDC login, callback, and step-up authentication: passed. Brute-force protection configured and visually verified.
- Project owner reports successful manual real-world conflict testing; see [E2E/release testing](docs/testing/E2E_AND_RELEASE_TESTING.md).

## Documentation

- [Beginner user guide](docs/USER_GUIDE.md)
- [Administrator guide](docs/ADMIN_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [API reference](docs/API_REFERENCE.md)
- [Security](docs/SECURITY.md)
- [E2E and release testing](docs/testing/E2E_AND_RELEASE_TESTING.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Changelog](CHANGELOG.md)
- [Release notes](RELEASE_NOTES.md)
- [Contributing](CONTRIBUTING.md)

## Production warning

The local Compose setup uses Keycloak development mode. It is not production configuration. Production requires HTTPS, hardened identity/database infrastructure, secret management, monitoring, backup/restore validation, least-privilege review and operational procedures. A passing test suite is not a production security certification.

## Keycloak step-up MFA (visual walkthrough)

See [Keycloak Browser Step-Up MFA — Visual Setup Guide](docs/KEYCLOAK_STEP_UP_SETUP.md) for the beginner-friendly configuration walkthrough, screenshots, ACR-to-LoA mapping, Browser-flow binding, test evidence and troubleshooting.
