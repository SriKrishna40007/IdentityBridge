from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "IdentityBridge"
    app_version: str = "0.1.0"
    app_environment: Literal["development", "testing", "production"] = "development"
    database_url: str
    log_level: str = "INFO"

    oidc_issuer_url: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    app_origin: str | None = None

    login_rate_limit: int = Field(default=10, gt=0)
    csrf_rate_limit: int = Field(default=30, gt=0)
    rate_limit_window_seconds: int = Field(default=60, gt=0)

    keycloak_admin_client_id: str = "identitybridge-admin-service"
    keycloak_admin_client_secret: str = Field(min_length=1)

    session_secret: str = Field(min_length=32)

    jit_worker_enabled: bool = False
    jit_worker_interval_seconds: int = Field(default=30, gt=0)
    jit_worker_batch_size: int = Field(default=50, ge=1, le=500)

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.app_environment == "production":
            if len(self.session_secret) < 64:
                raise ValueError("Production SESSION_SECRET must be at least 64 characters")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
