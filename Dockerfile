# Multi-stage Dockerfile for Faramesh Core
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir build wheel && \
    python -m pip install --upgrade pip

# Copy source and build package
COPY . .
RUN python -m build && \
    pip install --no-cache-dir dist/*.whl

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy installed package from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create non-root user
RUN useradd -m -u 1000 faramesh && \
    chown -R faramesh:faramesh /app

USER faramesh

# Expose port
EXPOSE 8000

# Health check (using /metrics endpoint as health check)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/metrics', timeout=2)" || exit 1

# Default command
CMD ["faramesh", "serve", "--host", "0.0.0.0", "--port", "8000"]
