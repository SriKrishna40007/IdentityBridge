# API Reference

The live OpenAPI interface at `/docs` is authoritative for the running build.

## Authentication
| Method | Path | Description |
|---|---|---|
| GET | `/auth/csrf` | Get session CSRF token |
| GET | `/auth/login` | Start OIDC login |
| GET | `/auth/callback` | OIDC callback |
| GET | `/auth/me` | Current session identity |
| POST | `/auth/logout` | Clear session |

## Privileged access
Base: `/api/v1/privileges`

| Method | Path | Access |
|---|---|---|
| POST | `/requests` | Authenticated user; request own subject |
| GET | `/requests` | Authenticated user; own requests |
| GET | `/pending` | `identity-admin` |
| POST | `/{request_id}/approve` | `identity-admin` |
| POST | `/{request_id}/reject` | `identity-admin` |

Create body:
```json
{
  "target_user_id": "keycloak-subject",
  "role": "identity-admin",
  "justification": "Explain the business need in at least twenty characters.",
  "duration_minutes": 60
}
```
Roles: `identity-admin`, `security-analyst`, `auditor`. Duration 1–480, default 60. Extra fields are rejected.

Decision body:
```json
{"comment": "Decision rationale."}
```
Comment optional, maximum 1000 characters.

## User administration
Base: `/api/v1/admin/users` (requires `identity-admin`): `POST /` provision, `GET /?username=...` search, `PATCH /{user_id}/status`, `GET /{user_id}/roles`, `POST /{user_id}/roles`, `DELETE /{user_id}/roles/{role_name}`. Privileged roles are rejected by direct role endpoints.

## Protected examples
- `GET /api/v1/access/admin`: `identity-admin`.
- `GET /api/v1/access/security`: `security-analyst` or `identity-admin`.
- `GET /api/v1/access/audit`: `auditor` or `identity-admin`.

Health: `GET /health/live`.

Approval and successful Keycloak role assignment are separate outcomes. Inspect request status; with `exclusive_role_writer=False`, an absent role may require manual reconciliation.
