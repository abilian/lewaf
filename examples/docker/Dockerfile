# LeWAF Production Dockerfile
# Multi-stage build for optimal image size and security

FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install --no-cache-dir uv

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# Install dependencies using uv
RUN uv sync --no-dev

# Create non-root user
RUN groupadd -r lewaf && useradd -r -g lewaf lewaf

# Copy configuration files
COPY examples/docker/lewaf.conf /app/config/lewaf.conf
COPY examples/docker/crs-setup.conf /app/config/crs-setup.conf

# Create directories for rules and logs
RUN mkdir -p /app/rules /app/logs /app/data && \
    chown -R lewaf:lewaf /app

# Switch to non-root user
USER lewaf

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Environment variables
ENV LEWAF_CONFIG=/app/config/lewaf.conf
ENV LEWAF_RULES_DIR=/app/rules
ENV LEWAF_LOG_LEVEL=INFO
ENV PYTHONUNBUFFERED=1

# Activate virtual environment for all commands
ENV PATH="/app/.venv/bin:$PATH"

# Default command (can be overridden)
CMD ["python", "-c", "import lewaf; print('✅ LeWAF container ready')"]
