# IdentityBridge Release Notes — JIT Privileged Access

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
- 160 tests passed with PostgreSQL integration enabled.
- 2 PostgreSQL lifecycle atomicity tests passed.
- Ruff and Python compilation passed.
- Four non-failing deprecation warnings.
- Project owner reports successful real-world conflict testing.

## Operational notes
This is not Microsoft Entra PIM. The worker is disabled by default. The current route uses `exclusive_role_writer=False`, so absent-role assignment is not blindly performed. Only verified JIT-owned roles may be automatically revoked. Local Compose Keycloak uses development mode.

## Status
Automated test gate: **PASS** for the recorded run. This is not production deployment authorization. Complete manual E2E evidence, production hardening, operational review and Git diff review before tagging/deployment.
