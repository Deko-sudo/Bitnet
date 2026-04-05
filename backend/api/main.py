# -*- coding: utf-8 -*-
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

from backend.api.dependencies import init_db
from backend.api.routers.auth import router as auth_router
from backend.api.routers.entries import router as entries_router

app = FastAPI(
    title="BEZ Password Manager API",
    description="Backend API for BEZ password manager",
    version="1.0.0"
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Do not leak sensitive exception details
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.on_event("startup")
async def on_startup() -> None:
    """Initialize persistence before serving requests."""
    init_db()


app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(entries_router, prefix="/api/entries", tags=["entries"])

if __name__ == "__main__":
    uvicorn.run("backend.api.main:app", host="127.0.0.1", port=8000, reload=True)
