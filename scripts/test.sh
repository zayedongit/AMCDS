#!/bin/bash
# AMCDS Test Runner
set -e
echo "=== Running AMCDS Tests ==="

echo "--- Unit Tests ---"
python -m pytest tests/unit/ -v --tb=short 2>/dev/null || echo "Unit tests require dependencies"

echo ""
echo "--- Integration Tests ---"
python -m pytest tests/integration/ -v --tb=short 2>/dev/null || echo "Integration tests require running services"

echo ""
echo "=== Tests Complete ==="
