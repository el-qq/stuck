# STUCK backend — matches the Python 3.14 dependency lock environment.
# Exact tag + multi-platform digest make the base image reproducible.
FROM python:3.14.6-slim-trixie@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015 AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# Application code and default conf.
COPY app ./app
COPY conf ./conf

# Non-root runtime user.
RUN useradd --create-home --uid 10001 stuck \
    && chown -R stuck:stuck /app
USER stuck

# Backend port (overridable at runtime via STUCK_BACKEND_PORT).
ENV STUCK_BACKEND_PORT=8000
EXPOSE 8000

# Container healthcheck hits the unauthenticated health endpoint (contract §3.7).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
port=os.environ.get('STUCK_BACKEND_PORT','8000'); \
sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=3).status==200 else 1)"

# Bind via env-driven port; single worker keeps the in-memory session store consistent.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${STUCK_BACKEND_PORT:-8000} --workers 1"]
