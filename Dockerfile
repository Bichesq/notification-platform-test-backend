# ========= STAGE 1: Base Image =========
FROM python:3.11-slim AS base

# Prevent Python from writing pyc files and buffering output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc build-essential libffi-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specification
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ========= STAGE 2: Build and Run =========
FROM base AS runtime

# Copy application code
COPY . .

# Expose FastAPI port
EXPOSE 8001

# Healthcheck to ensure app is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl --fail http://localhost:8001/health || exit 1

# Environment variables with defaults
ENV AWS_REGION=us-east-1
ENV APPLICATIONS_TABLE=applications
ENV API_KEYS_TABLE=api_keys
ENV ALLOWED_ORIGINS=*
ENV APP_PORT=8001
ENV APP_HOST=0.0.0.0

# Run the app using Uvicorn with hot-reload disabled (for production)
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
