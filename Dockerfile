# Сборка на базе облегченного образа Python
FROM python:3.11-slim

# Отключаем создание .pyc файлов и буферизацию (повышает скорость и безопасность логов)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Безопасность: Контейнер не должен запускаться от имени root (ограничение векторов атаки)
RUN addgroup --system appgroup && adduser --system --group appuser

# Установка системных зависимостей для сборки C-расширений (требуется для argon2 и ctypes)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Установка Python-библиотек бэкенда
# В реальном проекте здесь будет `COPY requirements.txt .` и `pip install -r requirements.txt`
RUN pip install --no-cache-dir fastapi uvicorn pydantic[email] sqlalchemy cryptography argon2-cffi python-multipart

# Копируем Исходный код (включая папку backend)
COPY backend/ ./backend/

# Даем права только созданному пользователю
RUN chown -R appuser:appgroup /app

# Переключение на безопасного пользователя
USER appuser

EXPOSE 8000

# Запуск FastAPI через Uvicorn
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
