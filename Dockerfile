FROM python:3.12-slim

# HF Spaces runs as a non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser . .

# Ensure static dirs exist
RUN mkdir -p web/static/css web/static/js

USER appuser

EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
