import math
import time
from collections.abc import Mapping
from typing import Any


def validate_oidc_assurance(
    claims: Mapping[str, Any],
    *,
    required_acr: str = "2",
    max_age_seconds: int = 300,
    now: float | None = None,
) -> None:
    """Require a specific OIDC assurance level and recent authentication.

    The caller must supply claims from an already signature-validated ID token.
    Raises ValueError when assurance or freshness requirements are not met.
    """
    if not isinstance(claims, Mapping):
        raise ValueError("Invalid OIDC claims")

    if not isinstance(required_acr, str) or not required_acr:
        raise ValueError("Invalid required ACR configuration")

    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, int)
        or max_age_seconds <= 0
    ):
        raise ValueError("Invalid authentication maximum age")

    acr = claims.get("acr")
    if not isinstance(acr, str) or acr != required_acr:
        raise ValueError("Required authentication assurance level not met")

    auth_time = claims.get("auth_time")
    if (
        isinstance(auth_time, bool)
        or not isinstance(auth_time, (int, float))
        or not math.isfinite(auth_time)
    ):
        raise ValueError("Missing or invalid authentication time")

    current_time = time.time() if now is None else now
    if (
        isinstance(current_time, bool)
        or not isinstance(current_time, (int, float))
        or not math.isfinite(current_time)
    ):
        raise ValueError("Invalid current time")

    age = current_time - auth_time

    if age < 0:
        raise ValueError("Authentication time is in the future")

    if age > max_age_seconds:
        raise ValueError("Authentication is too old")
