# Contributing

Follow `docs/development/setup.md` for setup.

Before changing code:
- Preserve fail-closed authorization and JIT ownership checks.
- Do not confuse the application OIDC client with the admin service client.
- Do not weaken conflict/manual-reconciliation behaviour to make tests pass.
- Keep the worker disabled by default unless an explicitly reviewed requirement changes it.

Required checks:
```bash
uv run pytest -q
RUN_POSTGRES_INTEGRATION=1 uv run pytest -q
uv run ruff check .
uv run python -m compileall -q src tests
```

Explain security/data-flow impact, add success/failure/conflict tests, document migrations, update docs/changelog, and never commit secrets, database dumps or personal data. Do not commit or release without repository-owner approval.
