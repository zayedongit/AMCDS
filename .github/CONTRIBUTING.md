# Contributing to AMCDS

## Branch Strategy

- `main` → stable releases
- `dev` → integration branch
- `feature/*` → new modules or features
- `fix/*` → bug fixes

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature dev`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `./scripts/test.sh`
6. Commit with clear messages
7. Push and create a Pull Request against `dev`

## Code Standards

- Python: Follow PEP 8, type hints required
- TypeScript: Strict mode enabled
- All new agents must extend `BaseAgent`
- All telemetry must use OCSF schema from `schema.py`
- All simulation must be deterministic (seeded RNG)

## Testing

- Unit tests: `tests/unit/`
- Integration tests: `tests/integration/`
- All PRs must pass existing tests
- New features require new tests
