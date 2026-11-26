FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/pyproject.toml /app/pyproject.toml
COPY backend/alembic.ini /app/alembic.ini
COPY backend/migrations /app/migrations
COPY backend/src /app/src

RUN pip install --upgrade pip && pip install .

EXPOSE 8000
CMD ["uvicorn", "netsentinel.main:app", "--host", "0.0.0.0", "--port", "8000"]
