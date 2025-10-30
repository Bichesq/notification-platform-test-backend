# ========= STAGE 1: Base Image =========
FROM python:3.11-slim AS base

# Prevent Python from writing pyc files and buffering output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc build-essential sqlite3 libffi-dev \
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

# Optional: Healthcheck to ensure app is running
HEALTHCHECK CMD curl --fail http://localhost:8001/ || exit 1

# Environment variable for database URL (defaults to SQLite)
ENV DATABASE_URL=sqlite:///./app.db

# Run the app using Uvicorn with hot-reload disabled (for production)
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
