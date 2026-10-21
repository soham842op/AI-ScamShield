from fastapi import APIRouter

from app.api.v1 import analyze, feedback

router = APIRouter(prefix="/api/v1")
router.include_router(analyze.router)
router.include_router(feedback.router)
