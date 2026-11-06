# IdentityBridge

Enterprise Identity and Access Management Security Platform.

## Purpose

IdentityBridge demonstrates enterprise identity security through:

- OpenID Connect and Single Sign-On
- Multi-Factor Authentication
- Role-Based Access Control
- Access policy evaluation
- Privileged access separation
- Security audit logging

## Architecture

The platform uses Keycloak as its identity provider,
FastAPI as its application layer, and PostgreSQL for persistence.

## Development

Requirements:
- Python 3.12+
- uv
- Docker Desktop

## Security

Never commit credentials, secrets, or production environment files.
