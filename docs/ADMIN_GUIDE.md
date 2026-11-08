# Administrator Guide

## Review a request
1. Sign in as a separate `identity-admin` account.
2. Retrieve `GET /api/v1/privileges/pending`.
3. Review requester, target, role, justification and requested duration.
4. Approve or reject using the request ID.
5. Inspect returned status and audit history.

Self-approval is prohibited. Decisions apply only to pending requests.

## Role management
Direct user-role endpoints support `standard-user`. Direct assignment/removal of `identity-admin`, `security-analyst` and `auditor` is blocked; use JIT.

The application client is `settings.oidc_client_id` / `OIDC_CLIENT_ID`. It is not the separate Keycloak administration service client.

## Ownership safeguards
- Existing role: pre-existing; do not remove it as JIT-owned.
- Confirmed JIT grant: eligible for expiry revocation.
- Unknown/contradictory ownership: manual reconciliation.
- Provider error: verify Keycloak state; do not assume success or failure.

The current route uses `exclusive_role_writer=False`. Do not change this or enable another writer without an explicit reviewed ownership model.

## Worker
Worker is disabled by default. Do not enable it until exclusive role-writer semantics, ownership, retry handling, monitoring, alerting and manual reconciliation are approved for the target environment.

## Keycloak permissions
Use a dedicated confidential service client and grant only the required `realm-management` permissions. Avoid broad realm-admin privileges.

## Incident handling
Preserve sanitized logs, inspect Keycloak role state, inspect JIT request and audit records, and reconcile ambiguous ownership through the approved operational process. Never put tokens, passwords or secrets in audit details.
