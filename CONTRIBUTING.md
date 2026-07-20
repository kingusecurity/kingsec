# Contributing to KingSec

Thank you for your interest in contributing to KingSec. This document outlines the guidelines for contributing to the project.

## Code of Conduct

This project is committed to providing a welcoming, inclusive, and harassment-free experience for everyone. Be respectful, constructive, and professional in all interactions.

## Getting Started

1. **Fork the repository** and clone your fork.
2. **Set up the development environment:**
   ```bash
   make install
   ```
3. **Run the quality gates before submitting:**
   ```bash
   make check
   ```

## Development Workflow

### Branch Naming
- `feature/<description>` — new features
- `fix/<description>` — bug fixes
- `docs/<description>` — documentation changes
- `refactor/<description>` — code refactoring
- `release/v<major>.<minor>.<patch>` — release branches

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

### Before Submitting

Run all quality gates:
```bash
make check
```

This runs:
- **Lint**: Ruff static analysis
- **Types**: mypy strict mode
- **Architecture**: import-linter hexagonal boundary enforcement
- **Security**: Bandit SAST + pip-audit dependency audit
- **Tests**: full test suite (pytest)

### Pull Request Process

1. Ensure all quality gates pass.
2. Update documentation if needed.
3. Add tests for new functionality.
4. Update the CHANGELOG.md with your changes.
5. Request review from a maintainer.

## Architecture

KingSec follows Clean Architecture (Hexagonal):
- **domain/** — pure business logic, no framework dependencies
- **application/** — use cases and ports (interfaces)
- **infrastructure/** — adapters (implementations of ports)
- **interfaces/** — API layer (FastAPI routes)
- **bootstrap/** — composition root (dependency injection wiring)

See [docs/FOUNDATION.md](docs/FOUNDATION.md) for the full blueprint.

## Security

- Never commit secrets, API keys, or credentials.
- Use `SecretStr` from Pydantic for sensitive configuration values.
- Run `make sec` to check for security issues before committing.
- Report security vulnerabilities privately per [SECURITY.md](SECURITY.md).

## Testing

- Write tests for all new functionality.
- Use pytest markers: `unit`, `integration`, `contract`, `e2e`, `slow`.
- Run tests with: `make test` or `pytest -v`.

## Questions?

Open a [discussion](https://github.com/kingusecurity/kingsec/discussions) or [issue](https://github.com/kingusecurity/kingsec/issues) on GitHub, or email **kingusecurity@gmail.com**.
