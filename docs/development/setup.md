# IdentityBridge Development Setup

This guide explains how to configure and run IdentityBridge from a fresh clone.

## Prerequisites

- Windows with Git Bash
- Docker Desktop
- Python 3.12 or newer
- uv

## 1. Configure environment variables

Copy the example configuration:

```bash
cp .env.example .env
```

Configure the values in `.env`:

- PostgreSQL username and password
- Keycloak bootstrap administrator username and password
- OIDC application client secret
- Dedicated Keycloak administration client secret
- Application database URL pointing to `identitybridge_app`
- Session signing secret of at least 32 characters

Never commit `.env` or share its contents.

## 2. Start infrastructure

From the project root, start PostgreSQL and Keycloak:

```bash
docker compose up -d
docker compose ps
```

Wait until PostgreSQL reports healthy and Keycloak has started.

Keycloak administration console: http://localhost:8180/admin/

## 3. Create the application database

PostgreSQL uses two separate databases:

- `identitybridge` — Keycloak persistence.
- `identitybridge_app` — IdentityBridge application persistence.

Create `identitybridge_app` if it does not already exist. Do not drop or recreate the Keycloak database.

```bash
docker exec identitybridge-postgres createdb -U identitybridge -O identitybridge identitybridge_app
```

## 4. Configure Keycloak

Open the Keycloak administration console:

http://localhost:8180/admin/

Sign in using the existing Keycloak administrator credentials.

Select or create the `identitybridge` realm.

### Application OIDC client

Configure the confidential client `identitybridge-api`:

- Client authentication: enabled
- Standard flow: enabled
- Direct access grants: disabled
- Valid redirect URI: `http://localhost:8000/auth/callback`
- Web origin: `http://localhost:8000`

Set its generated client secret as `OIDC_CLIENT_SECRET` in `.env`.

Configure the application roles: `admin`, `security`, `auditor`, and `identity-admin`.

### Administration service client

Configure `identitybridge-admin-service` as a confidential client with service accounts enabled.

Set its generated secret as `KEYCLOAK_ADMIN_CLIENT_SECRET` in `.env`.

Assign only the required `realm-management` roles:

- `query-users`
- `view-users`
- `manage-users`
- `query-clients`
- `view-clients`

Do not grant broad realm-administrator privileges to this service account.

## 5. Install Python dependencies

```bash
uv sync --all-groups
```

## 6. Apply database migrations

```bash
uv run alembic upgrade head
uv run alembic current
```

Alembic creates application tables inside `identitybridge_app`. It does not create the database itself.

## 7. Start the API

```bash
uv run uvicorn identitybridge.main:app --host 127.0.0.1 --port 8000
```

Health endpoint: http://localhost:8000/health/live

Interactive API documentation: http://localhost:8000/docs

## 8. Run quality checks

```bash
uv run pytest -v
uv run ruff check .
```

## Security notes

- Never commit `.env` or production environment files.
- Do not expose PostgreSQL or Keycloak development ports publicly.
- Keycloak `start-dev` is not a production configuration.
- Use HTTPS and secure session-cookie settings in production.
- Keep the administration service account least-privileged.
- Generate unique, strong secrets for each environment.
