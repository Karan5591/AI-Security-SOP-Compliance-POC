import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import batch_review, dependency, repo, review, sop
from app.core.config import get_settings
from app.db.postgres import close_connection, init_db
from app.llm.client import close_client

settings = get_settings()
logger = logging.getLogger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
    close_connection()
    close_client()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.include_router(sop.router)
app.include_router(review.router)
app.include_router(batch_review.router)
app.include_router(dependency.router)
app.include_router(repo.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """POC-only: surface the real error as JSON instead of a bare 500 plain-text
    response, so failures (e.g. LLM gateway unreachable) are debuggable from
    curl/Postman without needing to check docker logs every time. Tighten or
    remove this before anything resembling production use (see ERR-001/ERR-002
    in data/sop/error_handling.json - this deliberately breaks that rule for
    local dev convenience)."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "type": type(exc).__name__,
            "detail": str(exc),
        },
    )


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name}
