# ============================================================================
# CYBERSHEPPARD - Django Backend Dockerfile
# ============================================================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    libpq-dev \
    gcc \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create directories for SSH keys and backups
RUN mkdir -p /app/ssh-keys /app/tmp/backups /app/logs && \
    chmod 700 /app/ssh-keys

# Create app user
RUN useradd -m -u 1000 cybersheppard && \
    chown -R cybersheppard:cybersheppard /app

# Switch to app user
USER cybersheppard

EXPOSE 8001

# Run migrations and start server
CMD python manage.py migrate && \
    python manage.py runserver 0.0.0.0:8001
