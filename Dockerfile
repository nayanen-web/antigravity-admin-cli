# Dockerfile for agy-admin Cloud Run Batch Job
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and install
COPY pyproject.toml .
COPY agy_admin/ agy_admin/
RUN pip install --no-deps -e .

# Non-root user for security
RUN useradd -m -u 1000 appuser && \
    mkdir -p /home/appuser/.agy-admin && \
    chown -R appuser:appuser /app /home/appuser
USER appuser

ENTRYPOINT ["python", "-m", "agy_admin.batch_job"]
