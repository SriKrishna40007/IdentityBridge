from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health/live")
async def liveness() -> dict[str, str]:
    return {"status": "alive"}
