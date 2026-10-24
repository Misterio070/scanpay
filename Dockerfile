FROM python:3.11-slim

WORKDIR /app

# Install system build dependencies for C/Rust extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py ./
COPY src/ ./src/

# Default configuration
ENV SCANPAY_PORT=8484
ENV SCANPAY_PAYMENT_MODE=disabled
ENV SCANPAY_MERCHANT_WALLET=""
ENV SCANPAY_RPC_URL="https://api.devnet.solana.com"
ENV SCANPAY_PRICE_LAMPORTS=10000000

EXPOSE 8484

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8484/api/v1/health')" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8484"]