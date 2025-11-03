FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 coraza && chown -R coraza:coraza /app
USER coraza

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')"

# Default command
CMD ["python", "-m", "lewaf.proxy.cli", "--upstream", "http://backend:80", "--host", "0.0.0.0", "--port", "8080"]
