#!/bin/bash
# AMCDS Start Script
set -e
echo "=== Starting AMCDS ==="
docker compose up -d
echo "Waiting for services..."
sleep 10

echo ""
echo "=== AMCDS Services ==="
echo "Dashboard:     http://localhost:3000"
echo "API:           http://localhost:8080"
echo "Ray Dashboard: http://localhost:8265"
echo "Neo4j Browser: http://localhost:7474"
echo "Kafka:         localhost:9092"
echo "PostgreSQL:    localhost:5432"
echo "Redis:         localhost:6379"
echo ""
echo "Logs: docker compose logs -f"
