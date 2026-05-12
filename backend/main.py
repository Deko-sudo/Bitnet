# -*- coding: utf-8 -*-
import logging
import os
import time
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from contextlib import asynccontextmanager

from backend.api.v1.endpoints import auth, backups, breach, entries, fido2, generator, portability, totp, trash
from backend.database.session import init_db, AsyncSessionLocal
from backend.features.breach_monitor_async import AsyncBreachMonitorService

_breach_monitor: Optional[AsyncBreachMonitorService] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _breach_monitor
    # Startup
    init_db()
    _breach_monitor = AsyncBreachMonitorService(
        db_session_factory=AsyncSessionLocal,
        hibp_api_key=os.getenv("HIBP_API_KEY"),
    )
    await _breach_monitor.start()
    app.state.breach_monitor = _breach_monitor
    yield
    # Shutdown
    if _breach_monitor is not None:
        await _breach_monitor.stop()
        _breach_monitor = None

# Настройка безопасного логгера
logger = logging.getLogger("api_logger")
logger.setLevel(logging.INFO)
# Добавляем базовый stream handler, если не настроен
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(ch)

_disable_docs = os.getenv("BITNET_DISABLE_DOCS", "1").lower() in ("1", "true", "yes")

app = FastAPI(
    lifespan=lifespan,
    docs_url=None if _disable_docs else "/docs",
    redoc_url=None if _disable_docs else "/redoc",
    openapi_url=None if _disable_docs else "/openapi.json",
)

# CORS — restrict to known origins in production; no credentials needed (bearer token)
_cors_origins = os.getenv("CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:5173,http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins.split(",")],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# API routers must come BEFORE static mount so API paths are handled by FastAPI
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(entries.router, prefix="/api/v1/entries", tags=["Entries"])
app.include_router(trash.router, prefix="/api/v1/trash", tags=["Trash"])
app.include_router(fido2.router, prefix="/api/v1/fido2", tags=["FIDO2/WebAuthn"])
app.include_router(portability.router, prefix="/api/v1/portability", tags=["Import/Export"])
app.include_router(generator.router, prefix="/api/v1/generator", tags=["Generator"])
app.include_router(backups.router, prefix="/api/v1/backups", tags=["Backups"])
app.include_router(breach.router, prefix="/api/v1/breach", tags=["Breach Monitor"])
app.include_router(totp.router, prefix="/api/v1/totp", tags=["TOTP Authenticator"])


@app.get("/health", tags=["System"])
async def health_check():
    """Healthcheck with DB connectivity test."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "db": "unavailable"},
        )


# Serve frontend static files LAST — catch-all for SPA fallback
frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")


def _new_error_id() -> str:
    return uuid.uuid4().hex


def _error_response(status_code: int, message: str, error_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": message,
            "error_id": error_id,
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    error_id = _new_error_id()
    log_method = logger.warning if exc.status_code >= 500 else logger.info
    log_method(
        "http_exception error_id=%s status=%s method=%s path=%s exception=%s",
        error_id,
        exc.status_code,
        request.method,
        request.url.path,
        exc.__class__.__name__,
    )
    return _error_response(
        exc.status_code,
        "Request could not be processed.",
        error_id,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    error_id = _new_error_id()
    logger.info(
        "validation_error error_id=%s method=%s path=%s error_count=%s",
        error_id,
        request.method,
        request.url.path,
        len(exc.errors()),
    )
    return _error_response(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "Invalid request.",
        error_id,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    error_id = _new_error_id()
    logger.error(
        "unhandled_exception error_id=%s method=%s path=%s exception=%s",
        error_id,
        request.method,
        request.url.path,
        exc.__class__.__name__,
    )
    return _error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "Internal server error.",
        error_id,
    )



@app.middleware("http")
async def secure_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.middleware("http")
async def secure_logging_middleware(request: Request, call_next):
    """
    Zero-Trust Middleware для HTTP-отслеживания.
    Абсолютно запрещено логировать:
      - тела запросов (там могут быть `password` или данные для шифрования)
      - заголовки (особенно `Authorization`, `Cookie` или кастомные API-токены)
    """
    start_time = time.time()

    # Извлечение безопасных метаданных запроса
    method = request.method
    url = request.url.path
    client_ip = request.client.host if request.client else "unknown"

    response = await call_next(request)

    process_time = time.time() - start_time
    status_code = response.status_code

    # Логгируем исключительно "сухие" технические данные
    logger.info(
        "request method=%s path=%s client=%s status=%s latency=%.4fs",
        method,
        url,
        client_ip,
        status_code,
        process_time,
    )

    return response
