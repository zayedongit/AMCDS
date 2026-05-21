#!/bin/bash
# AMCDS Setup Script
set -e

echo "=== AMCDS Setup ==="

# Check Docker
if ! command -v docker &> /dev/null; then echo "ERROR: Docker not installed"; exit 1; fi
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then echo "ERROR: Docker Compose not installed"; exit 1; fi
echo "✓ Docker found"

# Create .env from example
if [ ! -f .env ]; then cp .env.example .env; echo "✓ Created .env from .env.example"; else echo "✓ .env already exists"; fi

# Build images
echo "Building Docker images..."
docker compose build
echo "✓ Images built successfully"
echo ""
echo "=== Setup complete! Run: docker compose up ==="
