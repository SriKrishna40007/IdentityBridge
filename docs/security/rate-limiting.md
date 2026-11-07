# Authentication Rate Limiting

## Configuration

IdentityBridge uses PostgreSQL-backed fixed-window rate limiting.

| Endpoint | Default limit |
|---|---:|
| GET /auth/login | 10 requests per 60 seconds |
| GET /auth/csrf | 30 requests per 60 seconds |

Environment variables:
- LOGIN_RATE_LIMIT=10
- CSRF_RATE_LIMIT=30
- RATE_LIMIT_WINDOW_SECONDS=60

The OIDC callback is excluded.

## Storage and privacy

Counters are stored in PostgreSQL in the rate_limit_counters table. Client identifiers are HMAC-SHA256 hashed using the application session secret. Raw client IP addresses are not persisted. Login and CSRF scopes use separate hashes.

PostgreSQL atomic upserts ensure concurrent workers share counters. Windows are UTC-aligned fixed windows, so requests around a boundary can produce a short burst.

## Response behavior

- Requests within the limit proceed.
- Requests above the limit receive HTTP 429 and Retry-After.
- Rate-limit database failures return HTTP 503 (fail closed).
- The middleware does not trust X-Forwarded-For.

For reverse-proxy deployments, configure trusted-proxy handling at the server boundary.

## Counter retention

Counters are operational state, not audit records. Run scripts/cleanup_rate_limit_counters.sql daily.

From the repository root, execute:

docker exec -i identitybridge-postgres psql -U identitybridge -d identitybridge_app < scripts/cleanup_rate_limit_counters.sql

Schedule this command daily using Windows Task Scheduler. Ensure Docker Desktop is running first.

The cleanup deletes only rate-limit counters older than 24 hours. It does not modify audit_events, Keycloak data, or user accounts.

## Operational checks

PostgreSQL health:
docker inspect --format='{{.State.Health.Status}}' identitybridge-postgres

Migration:
uv run alembic current

Review HTTP 429 responses as rate-limit activity and HTTP 503 responses as database availability incidents.

## Security considerations

- Keep SESSION_SECRET private and consistent across application workers.
- Never expose database credentials in logs or documentation.
- Do not disable fail-closed behavior to hide database outages.
- Review configured limits against real traffic before production rollout.
- Use HTTPS and production session-cookie settings in production.
