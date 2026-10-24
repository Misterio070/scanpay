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

# Copy application code and discovery assets
COPY main.py ./
COPY src/ ./src/
COPY llms.txt ./
COPY bazaar.json ./
COPY glama.json ./
COPY package.json ./
COPY smithery.yaml ./
COPY README.md ./
COPY social-preview.svg ./

# Default configuration
ENV SCANPAY_PORT=8484
ENV SCANPAY_PAYMENT_MODE=mainnet
ENV SCANPAY_MERCHANT_WALLET="JDKXvegmW5j4sAJPB6YCA9ffJbN422WLMmCWCcpy1vm4"
ENV SCANPAY_MERCHANT_EVM_WALLET="0xb295E606F38C363b476FC546c27226B5fBcAAEFA"
ENV SCANPAY_RPC_URL="https://api.mainnet-beta.solana.com"
ENV SCANPAY_BASE_RPC="https://mainnet.base.org"
ENV SCANPAY_PRICE_LAMPORTS=700000

EXPOSE 8484

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8484/api/v1/health')" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8484"]