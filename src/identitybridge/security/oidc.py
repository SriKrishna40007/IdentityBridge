from authlib.integrations.starlette_client import OAuth

from identitybridge.config.settings import Settings


def create_oidc_client(settings: Settings):
    oauth = OAuth()

    oauth.register(
        name="keycloak",
        server_metadata_url=(
            f"{settings.oidc_issuer_url.rstrip('/')}"
            "/.well-known/openid-configuration"
        ),
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        client_kwargs={"scope": "openid profile email"},
    )

    return oauth
