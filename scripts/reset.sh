#!/bin/bash
# AMCDS Reset Script - Clears all state
set -e
echo "=== Resetting AMCDS ==="
docker compose down -v --remove-orphans
echo "✓ Containers stopped and volumes removed"
echo "Run 'docker compose up' to start fresh"
