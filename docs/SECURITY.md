# Security Model

## Controls in the inspected application
- Keycloak OIDC authentication.
- Role-protected routes and fresh provider role verification for protected authorization.
- Fail-closed authorization when role verification cannot be completed.
- Privileged roles separated from direct role assignment/removal.
- JIT self-approval prevention and bounded duration.
- Audit detail allowlist.
- Request ID, origin validation, CSRF, rate limiting and security-header middleware.
- Session cookie `identitybridge_session`, 30-minute max age, `SameSite=Lax`; secure cookie in production environment.
- Expiry worker disabled by default.
- Ownership checks before automatic revocation.

## Secrets
Never commit `.env`. Use unique strong secrets per environment. Do not expose tokens, passwords, cookies, database credentials or personal data in logs, screenshots or issue reports. Keep local database and Keycloak ports private.

## JIT ownership
Only a role with verified JIT ownership can be automatically revoked. Pre-existing or uncertain roles are preserved/manual-reconciliation cases. Current approval route uses `exclusive_role_writer=False`, so the application does not assume it can assign an absent role as the exclusive writer.

## Production limitations
Compose uses Keycloak development mode and is not production configuration. Production requires HTTPS, hardened Keycloak/PostgreSQL, secret management, monitoring, alerting, backup/restore drills, access reviews and operational procedures. This document is not a penetration-test certificate or production security certification.
