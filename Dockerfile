FROM python:3.11-slim

LABEL maintainer="AMCDS Contributors"
LABEL description="AMCDS Simulation Engine with Ray"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY simulation/ ./simulation/
COPY agents/ ./agents/
COPY messaging/ ./messaging/
COPY configs/ ./configs/
COPY tests/ ./tests/

# Copy package init
COPY setup.py .

# Install the project
RUN pip install -e .

EXPOSE 8000 8265

# Start Ray head node and then the simulation engine
CMD ["bash", "-c", "ray start --head --dashboard-host=0.0.0.0 --num-cpus=4 --object-store-memory=$RAY_OBJECT_STORE_MEMORY && python -m simulation.main"]
