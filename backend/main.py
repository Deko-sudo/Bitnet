# -*- coding: utf-8 -*-
from fastapi import FastAPI, Request
import time
import logging

from backend.api.v1.endpoints import auth, entries, trash
from backend.database.session import init_db

# Настройка безопасного логгера
logger = logging.getLogger("api_logger")
logger.setLevel(logging.INFO)
# Добавляем базовый stream handler, если не настроен
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(ch)

app = FastAPI(
    title="BitNet API", 
    description="E2EE Password Manager API (Zero-Trust Architecture)",
    version="1.0.0"
)

# Подключение роутеров из пространства имен API
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(entries.router, prefix="/api/v1/entries", tags=["Entries"])
app.include_router(trash.router, prefix="/api/v1/trash", tags=["Trash"])


@app.on_event("startup")
def _on_startup() -> None:
    init_db()

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
    logger.info(f"[{method}] {url} | IP: {client_ip} | Status: {status_code} | Latency: {process_time:.4f}s")
    
    return response

@app.get("/health", tags=["System"])
def health_check():
    """Простейший эндпоинт для мониторинга."""
    return {"status": "ok", "message": "BitNet Server is highly secure and operational."}
