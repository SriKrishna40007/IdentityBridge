# IdentityBridge v2.1.0 Release Notes — JIT Privileged Access and Step-Up Authentication

## Step-up security
- Privileged approval requires the `identity-admin` role and recent OIDC step-up authentication.
- Step-up requires ACR 2 and authentication freshness within 300 seconds.


## Summary
Adds an application-level just-in-time privileged-access request and approval workflow using FastAPI, Keycloak and PostgreSQL.

## Included
- OIDC sign-in and role-protected APIs.
- Self-service privileged request and administrator approval/rejection.
- Bounded request duration and decision comments.
- Audit lifecycle records.
- Ownership-aware expiry/revocation, retries and manual reconciliation.
- PostgreSQL concurrency and atomicity coverage.

## Validation
- Full test suite: 197 passed, 2 skipped; PostgreSQL integration separately: 2 passed.
- 2 PostgreSQL lifecycle atomicity tests passed.
- Ruff passed.
- Four non-failing deprecation warnings.
- Manual OIDC login, callback and step-up smoke tests passed; brute-force protection configured and visually verified.

## Operational notes
This is not Microsoft Entra PIM. The worker is disabled by default. The current route uses `exclusive_role_writer=False`, so absent-role assignment is not blindly performed. Only verified JIT-owned roles may be automatically revoked. Local Compose Keycloak uses development mode.

## Status
Automated test gate: **PASS** for the recorded run. This is not production deployment authorization. Complete manual E2E evidence, production hardening, operational review and Git diff review before tagging/deployment.
