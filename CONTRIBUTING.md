# Contributing to mctl-api

Thank you for your interest in contributing to mctl-api! This guide will help you get started.

## Prerequisites

- **Go 1.25+**
- **Docker**

## Local Development

Start the API server locally with authentication disabled:

```bash
AUTH_REQUIRED=false go run cmd/api/main.go
```

## Testing

Run unit tests:

```bash
go test ./...
```

Run end-to-end tests:

```bash
cd e2e && go test -v
```

## Code Style

All contributions must follow these style guidelines:

- **Format code** with `go fmt ./...`
- **Vet code** with `go vet ./...`
- **Lint code** with `golangci-lint run`

Please ensure all three pass before submitting a pull request.

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/). Each commit message should be structured as:

```
<type>: <description>

[optional body]
```

Types:

- `feat:` — a new feature
- `fix:` — a bug fix
- `chore:` — maintenance tasks, dependency updates
- `docs:` — documentation changes
- `test:` — adding or updating tests
- `refactor:` — code changes that neither fix a bug nor add a feature
- `ci:` — CI/CD configuration changes

## Pull Request Process

1. **Fork** the repository.
2. **Create a branch** from `main` with a descriptive name:
   - `feat/add-tenant-api`
   - `fix/auth-token-validation`
3. Make your changes, following the code style and commit conventions above.
4. Push your branch and open a **pull request** against `main`.
5. PRs are merged with a **merge commit** (`gh pr merge --merge --delete-branch`), never squash. The feature branch must stay visible in the git graph.

## Questions?

If you have questions about contributing, feel free to open an issue for discussion.
