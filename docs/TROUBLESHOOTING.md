# Troubleshooting

## API startup
Run `uv sync --all-groups`; check required `.env` values without printing them; verify `docker compose ps`; check `uv run alembic current`.

## PostgreSQL
Ensure service is healthy, host port matches Compose, and `DATABASE_URL` targets `identitybridge_app`, not Keycloak's `identitybridge` database. Do not drop the persistent volume to troubleshoot.

## OIDC login
Verify Keycloak issuer, realm, application client, redirect URI and client secret. Never paste secrets into a support request.

## 401/403
401: sign in again. 403: check the user's application-client role and requested operation. Privileged role changes must use JIT.

## 409
An outstanding request may already exist or the request may no longer be pending. Retrieve request history/current pending state before retrying.

## Approved but not active
Approval and provider role assignment are separate. With `exclusive_role_writer=False`, an absent role may require manual reconciliation. Inspect status and audit records; do not manually mark ownership.

## Expiry not running
Worker is disabled by default. If deliberately enabled, inspect worker logs, database state, ownership markers and Keycloak state. Unknown ownership is not auto-revoked.

## Checks
```bash
uv run pytest -q
RUN_POSTGRES_INTEGRATION=1 uv run pytest -q
uv run ruff check .
uv run python -m compileall -q src tests
```
