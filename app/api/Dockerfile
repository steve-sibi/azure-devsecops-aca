# app/api/Dockerfile
FROM python:3.11-slim

# Keep Python tidy and unbuffered
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Optional build tools for some wheels
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY api/requirements.txt ./requirements.txt
# hadolint ignore=DL3013,DL3042
RUN python -m pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir --prefer-binary -r requirements.txt

COPY common/ ./common/
COPY api/ .

# Run as a non-root user (least-privilege)
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Expose container port (configurable via $PORT for portability)
EXPOSE 8000
ENV PORT=8000

# Use sh -c to allow env var expansion; enable proxy headers for ACA ingress
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT} --proxy-headers"]
