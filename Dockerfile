FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY src/ ./src/
COPY policies/ ./policies/
COPY alembic.ini ./
COPY alembic/ ./alembic/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 8000

# Set environment variables with defaults
ENV FARACORE_HOST=0.0.0.0
ENV FARACORE_PORT=8000
ENV FARACORE_ENABLE_CORS=1
ENV FARA_DB_BACKEND=sqlite
ENV FARA_SQLITE_PATH=/app/data/actions.db

# Run migrations and start server
CMD ["sh", "-c", "faracore migrate && faracore serve --host ${FARACORE_HOST} --port ${FARACORE_PORT}"]
