#!/bin/bash
# AMCDS Seed Data Script
set -e
echo "=== Seeding AMCDS Data ==="
echo "Creating Kafka topics..."
docker compose exec -T amcds-engine python -c "from simulation.main import _create_topics; _create_topics('kafka:9092')" 2>/dev/null || echo "Topics may already exist"
echo "✓ Seed complete"
