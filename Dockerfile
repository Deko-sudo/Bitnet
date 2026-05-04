# syntax=docker/dockerfile:1

# ===========================================================================
# STAGE 1: Rust Crypto Build (Maturin + PyO3)
# Uses Python + Rust to build the PyO3 extension wheel
# ===========================================================================
FROM rust:1.78-slim AS rust-builder

# Install build deps and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build

# ---- Dependency caching via cargo-chef pattern ----
# Copy Cargo manifests first to cache dependency downloads
COPY backend/core/Cargo.toml backend/core/Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo fetch && \
    rm -rf src

# Copy actual source code (invalidates cache when code changes)
COPY backend/core/src ./src

# Build the wheel via maturin
RUN pip install --no-cache-dir maturin && \
    maturin build --release --out /wheels

# ===========================================================================
# STAGE 2: Frontend Build (Vite + React)
# ===========================================================================
FROM node:20-slim AS frontend-builder

WORKDIR /frontend

# Copy package files first (layer caching)
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --frozen-lockfile --ignore-scripts

# Copy source and build
COPY frontend/ .
RUN npm run build

# ===========================================================================
# STAGE 3: Production Runtime (Python slim — minimal)
# ===========================================================================
FROM python:3.11-slim AS production

# Install minimal runtime deps + create non-root user
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r bitnet && \
    useradd -r -g bitnet -d /app -s /sbin/nologin bitnet

WORKDIR /app

# ---- Install the pre-built Rust wheel ----
COPY --from=rust-builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -f /tmp/*.whl

# ---- Install Python dependencies ----
COPY requirements.txt .
RUN pip install --no-cache-dir \
    uvicorn[standard] \
    -r requirements.txt && \
    rm -rf /root/.cache/pip

# ---- Copy application code ----
COPY backend/ backend/
COPY pyproject.toml .
COPY alembic.ini .
COPY alembic/ alembic/

# ---- Copy built frontend static files ----
COPY --from=frontend-builder /frontend/dist/ frontend/dist/

# ---- Set up data directory and ownership ----
RUN mkdir -p /app/data && \
    chown -R bitnet:bitnet /app

# ---- Drop to non-root user ----
USER bitnet

# ---- Environment ----
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BITNET_SERVER_WRAP_KEY_FILE=/run/secrets/server_key \
    SQLALCHEMY_DATABASE_URL=sqlite:////app/data/bitnet.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# SECURITY: Single worker to prevent AES-GCM nonce collision across processes.
# Multiple workers sharing the same SQLite DB increase birthday-paradox risk for
# random 96-bit nonces. Upgrade to AES-GCM-SIV or a counter nonce before scaling.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--loop", "uvloop"]
