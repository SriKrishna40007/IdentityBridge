import pytest

from identitybridge.security.oidc_assurance import validate_oidc_assurance

NOW = 1_800_000_000


def valid_claims() -> dict[str, object]:
    return {
        "sub": "test-user",
        "acr": "2",
        "auth_time": NOW - 120,
    }


def test_accepts_required_acr_and_recent_authentication() -> None:
    validate_oidc_assurance(valid_claims(), now=NOW)


@pytest.mark.parametrize(
    "acr",
    [None, "", "1", "3", 2, ["2"]],
)
def test_rejects_missing_or_incorrect_acr(acr: object) -> None:
    claims = valid_claims()
    claims["acr"] = acr

    with pytest.raises(ValueError, match="assurance"):
        validate_oidc_assurance(claims, now=NOW)


@pytest.mark.parametrize(
    "auth_time",
    [None, "1799999880", True, float("nan"), float("inf"), float("-inf")],
)
def test_rejects_missing_or_invalid_auth_time(auth_time: object) -> None:
    claims = valid_claims()
    claims["auth_time"] = auth_time

    with pytest.raises(ValueError, match="authentication time"):
        validate_oidc_assurance(claims, now=NOW)


def test_rejects_authentication_older_than_maximum_age() -> None:
    claims = valid_claims()
    claims["auth_time"] = NOW - 301

    with pytest.raises(ValueError, match="too old"):
        validate_oidc_assurance(claims, now=NOW)


def test_accepts_authentication_at_maximum_age_boundary() -> None:
    claims = valid_claims()
    claims["auth_time"] = NOW - 300

    validate_oidc_assurance(claims, now=NOW)


def test_rejects_future_authentication_time() -> None:
    claims = valid_claims()
    claims["auth_time"] = NOW + 1

    with pytest.raises(ValueError, match="future"):
        validate_oidc_assurance(claims, now=NOW)


def test_rejects_invalid_maximum_age() -> None:
    with pytest.raises(ValueError, match="maximum age"):
        validate_oidc_assurance(
            valid_claims(),
            max_age_seconds=0,
            now=NOW,
        )
