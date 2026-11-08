import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from identitybridge.api.routes.access import router as access_router
from identitybridge.api.routes.auth import router as auth_router
from identitybridge.api.routes.health import router as health_router
from identitybridge.api.routes.privileges import router as privileges_router
from identitybridge.api.routes.users import router as users_router
from identitybridge.application.privilege_expiry_worker import (
    process_expired_privileges,
)
from identitybridge.config.settings import Settings, get_settings
from identitybridge.infrastructure.database import SessionLocal
from identitybridge.infrastructure.keycloak.admin_client import KeycloakAdminClient
from identitybridge.security.csrf import CSRFMiddleware
from identitybridge.security.headers import SecurityHeadersMiddleware
from identitybridge.security.oidc import create_oidc_client
from identitybridge.security.origin import OriginValidationMiddleware
from identitybridge.security.rate_limit import RateLimitMiddleware
from identitybridge.security.request_id import RequestIDMiddleware

logger = logging.getLogger(__name__)


async def run_jit_expiry_worker(application: FastAPI) -> None:
    """Run the JIT expiry worker until application shutdown."""
    settings = application.state.settings
    admin = application.state.keycloak_admin

    while True:
        db = SessionLocal()

        try:
            await process_expired_privileges(
                db,
                admin,
                client_id=settings.oidc_client_id,
                batch_size=settings.jit_worker_batch_size,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error("JIT expiry worker iteration failed")
        finally:
            db.close()

        await asyncio.sleep(settings.jit_worker_interval_seconds)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        worker_task = None

        if settings.jit_worker_enabled:
            worker_task = asyncio.create_task(
                run_jit_expiry_worker(application),
                name="identitybridge-jit-expiry-worker",
            )

        try:
            yield
        finally:
            if worker_task is not None:
                worker_task.cancel()

                try:
                    await worker_task
                except asyncio.CancelledError:
                    pass

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Enterprise Identity and Access Management Security Platform",
        lifespan=lifespan,
    )

    application.state.settings = settings
    application.state.oauth = create_oidc_client(settings)
    application.state.keycloak_admin = KeycloakAdminClient(settings)

    redirect = urlsplit(settings.oidc_redirect_uri)
    trusted_origin = settings.app_origin or f"{redirect.scheme}://{redirect.netloc}"

    application.add_middleware(
        OriginValidationMiddleware,
        trusted_origin=trusted_origin,
    )

    application.add_middleware(CSRFMiddleware)
    application.add_middleware(RateLimitMiddleware)
    application.add_middleware(RequestIDMiddleware)

    application.add_middleware(
        SecurityHeadersMiddleware,
        enable_hsts=settings.app_environment == "production",
    )

    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="identitybridge_session",
        max_age=1800,
        same_site="lax",
        https_only=settings.app_environment == "production",
    )

    @application.get("/", tags=["Platform"])
    async def root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "status": "running",
            "documentation": "/docs",
        }

    application.include_router(health_router)
    application.include_router(auth_router)
    application.include_router(access_router)
    application.include_router(users_router)
    application.include_router(privileges_router)

    return application


app = create_app()
