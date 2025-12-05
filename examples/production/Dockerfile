# Production Dockerfile for LeWAF
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
COPY rules/ ./rules/
COPY coraza.conf ./
COPY examples/production/app.py ./
COPY examples/production/config.py ./

# Install dependencies
RUN uv sync --frozen

# Create non-root user
RUN useradd -m -u 1000 lewaf && \
    chown -R lewaf:lewaf /app

# Create log directory
RUN mkdir -p /var/log/lewaf && \
    chown lewaf:lewaf /var/log/lewaf

# Switch to non-root user
USER lewaf

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uv", "run", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
