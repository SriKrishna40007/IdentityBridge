# E2E, Conflict and Release Testing

## Recorded automated results
Commands executed successfully:

```bash
uv run pytest -q tests/test_privilege_lifecycle.py tests/test_privilege_expiry_worker.py tests/test_postgres_lifecycle_atomicity.py
RUN_POSTGRES_INTEGRATION=1 uv run pytest -q tests/test_postgres_lifecycle_atomicity.py
RUN_POSTGRES_INTEGRATION=1 uv run pytest -q
uv run ruff check .
uv run python -m compileall -q src tests
```

| Gate | Result |
|---|---:|
| Targeted JIT lifecycle/worker | 22 passed; 2 PostgreSQL tests skipped in this invocation because integration flag was not set |
| PostgreSQL atomicity | 2 passed |
| Full suite with PostgreSQL integration | 160 passed |
| Ruff | Passed |
| Python compilation | Passed |

Four deprecation warnings were emitted by Starlette/httpx, Authlib/httpx integration and the deprecated FastAPI 422 constant. They did not fail the run.

## Manual conflict validation
The project owner reports successful real-world conflict testing. This is recorded as owner-reported manual validation, distinct from automated test evidence. Scenario coverage to retain in a formal evidence pack:
- Concurrent/duplicate requests for the same target and role.
- Self-approval attempts.
- Repeated/conflicting approve/reject decisions.
- Direct privileged-role assignment/removal attempts.
- Pre-existing role versus JIT-owned role.
- Unknown/contradictory ownership.
- Keycloak failure during grant/revoke.
- Worker interruption and stale-claim recovery.
- Confirmation that pre-existing roles are not removed.

Do not infer exact scenario results from this list. Attach actual sanitized logs/test records if audit-grade evidence is needed.

## Manual E2E smoke test
Use a dedicated test realm and test users:
1. Start PostgreSQL and Keycloak.
2. Start the API and confirm `GET /health/live`.
3. Sign in as a normal test user through `/auth/login`; confirm `/auth/me`.
4. Submit a JIT request for that user's own subject.
5. Confirm it appears in `/api/v1/privileges/requests`.
6. Sign in as a separate `identity-admin`; inspect `/api/v1/privileges/pending`.
7. Approve or reject; inspect returned status and audit event.
8. Verify protected access and direct privileged-role operations.
9. Verify pre-existing role preservation.
10. Test expiry only with a known JIT-owned role in a controlled environment.
11. Sign out and confirm session cleared.

Current route uses `exclusive_role_writer=False`: absent-role assignment may require manual reconciliation. Worker is disabled by default; do not enable it merely to make a smoke test pass.

## Release checklist
- [x] Targeted JIT tests pass.
- [x] PostgreSQL lifecycle atomicity tests pass.
- [x] Full suite passes with PostgreSQL integration enabled.
- [x] Ruff passes.
- [x] Python compilation passes.
- [x] Owner reports successful real-world conflict testing.
- [ ] Manual E2E evidence recorded for intended release environment.
- [ ] Full staged and unstaged Git diff reviewed.
- [ ] No secrets, `.env`, dumps or personal data included.
- [ ] Migration and rollback strategy reviewed.
- [ ] Production configuration and operational controls reviewed.
- [ ] Worker enablement explicitly approved if intended; otherwise leave disabled.
- [ ] Version/tag and rollback plan approved.

## Release decision
Automated test gate: **PASS** (160 passed, including PostgreSQL integration). Manual conflict testing: **reported successful by project owner**. Production release approval is not implied: local Keycloak uses development mode, and deployment-specific E2E, security hardening, monitoring, backup/restore and worker ownership controls still require review.
