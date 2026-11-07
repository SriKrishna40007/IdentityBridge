\# IdentityBridge



Enterprise Identity and Access Management Security Platform.



\## Purpose



IdentityBridge demonstrates enterprise identity security through:



\- OpenID Connect (OIDC) and Single Sign-On (SSO)

\- Multi-Factor Authentication (MFA)

\- Role-Based Access Control (RBAC)

\- Access policy evaluation

\- Privileged access separation

\- Security audit logging



\## Architecture



The platform uses Keycloak as its identity provider, FastAPI as its application layer, and PostgreSQL for persistence.



\## Development



See \[Development Setup](docs/development/setup.md) for complete installation and configuration instructions.



\*\*Requirements:\*\*



\- Python 3.12+

\- uv

\- Docker Desktop



\## Security



Never commit credentials, secrets, or production environment files.



\## Authentication Rate Limiting



IdentityBridge protects login and CSRF-token endpoints with PostgreSQL-backed fixed-window rate limiting.



Default limits:



\- Login: 10 requests per client IP per 60 seconds.

\- CSRF-token requests: 30 requests per client IP per 60 seconds.



Requests above the configured limit receive HTTP 429. Rate-limit storage failures fail closed with HTTP 503.



See \[Authentication Rate Limiting](docs/security/rate-limiting.md) for configuration, privacy, proxy considerations, and counter retention.



