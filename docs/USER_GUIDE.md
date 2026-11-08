# Beginner User Guide

## What is a role?
A role is a named permission set. `standard-user` is ordinary access. `identity-admin`, `security-analyst` and `auditor` are privileged roles.

## Sign in
Start the API and Keycloak, then open `http://localhost:8000/auth/login`. Authenticate through Keycloak. Check the current session at `GET /auth/me`.

## Request privileged access
Send an authenticated `POST /api/v1/privileges/requests`:

```json
{
  "target_user_id": "YOUR_KEYCLOAK_SUBJECT",
  "role": "security-analyst",
  "justification": "I need access to investigate approved incident INC-12345.",
  "duration_minutes": 60
}
```

The subject must belong to the signed-in user. Justification length is 20–2000 characters. Duration is 1–480 minutes; default is 60. Only the three privileged roles listed above are accepted.

List your requests with `GET /api/v1/privileges/requests`.

## Administrator decision
An `identity-admin` lists pending requests at `GET /api/v1/privileges/pending`, then calls `POST /api/v1/privileges/{request_id}/approve` or `/reject`. Optional body:

```json
{"comment": "Approved for the incident response window."}
```

A requester cannot approve their own request. A decision can only be made while the request is pending.

## What approval means
Approval records the decision and invokes the grant workflow. It does not guarantee automatic role assignment. The current route uses `exclusive_role_writer=False`; an absent role may require manual reconciliation. Existing roles are treated as pre-existing and are not JIT-owned.

## Expiry
The worker is disabled by default. If enabled after operational review, it may revoke only roles proven to have been granted by JIT. Pre-existing, unknown or contradictory ownership is not automatically revoked.

## Sign out
Call `POST /auth/logout`.

## Common status codes
- `401`: authenticate or refresh the session.
- `403`: authorization denied or prohibited privileged direct-role operation.
- `404`: request not found.
- `409`: conflicting request or request no longer pending.
- `422`: invalid request fields.
- `502`: identity-provider operation failed.
- `503`: authorization/provider verification unavailable; access fails closed.
