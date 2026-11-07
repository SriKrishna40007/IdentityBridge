from typing import Annotated

from fastapi import APIRouter, Depends

from identitybridge.security.authorization import require_roles

router = APIRouter(prefix="/api/v1/access", tags=["Role-protected access"])


@router.get("/admin")
async def admin_access(
    user: Annotated[dict, Depends(require_roles("identity-admin"))],
) -> dict[str, str]:
    return {"access": "granted", "area": "administration"}


@router.get("/security")
async def security_access(
    user: Annotated[
        dict,
        Depends(require_roles("security-analyst", "identity-admin")),
    ],
) -> dict[str, str]:
    return {"access": "granted", "area": "security-operations"}


@router.get("/audit")
async def audit_access(
    user: Annotated[
        dict,
        Depends(require_roles("auditor", "identity-admin")),
    ],
) -> dict[str, str]:
    return {"access": "granted", "area": "audit"}
