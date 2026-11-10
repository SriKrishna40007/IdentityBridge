import pytest
from pydantic import ValidationError

from identitybridge.config.settings import Settings


def build_settings(**overrides):
    values = {
        "database_url": "sqlite:///./test.db",
        "oidc_issuer_url": "http://localhost:8180/realms/test",
        "oidc_client_id": "test-client",
        "oidc_client_secret": "test-client-secret",
        "oidc_redirect_uri": "http://localhost:8000/auth/callback",
        "keycloak_admin_client_secret": "test-admin-secret",
        "session_secret": "d" * 32,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    "environment",
    ["development", "testing", "production"],
)
def test_supported_environments(environment):
    secret = "s" * 64 if environment == "production" else "d" * 32

    settings = build_settings(
        app_environment=environment,
        session_secret=secret,
    )

    assert settings.app_environment == environment


def test_unknown_environment_is_rejected():
    with pytest.raises(ValidationError):
        build_settings(app_environment="prod")


def test_production_rejects_short_session_secret():
    with pytest.raises(ValidationError):
        build_settings(
            app_environment="production",
            session_secret="s" * 32,
        )


def test_production_accepts_long_session_secret():
    settings = build_settings(
        app_environment="production",
        session_secret="s" * 64,
    )

    assert settings.app_environment == "production"
