# Contributing

## Setup

```bash
uv sync
pnpm install
```

## Checks

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
pnpm lint && pnpm typecheck && pnpm test
```

## Rules

- Sign the [CLA](CLA.md) in your first pull request.
- Core code (`packages/`, `services/`, `apps/`, `spec/`) is Apache-2.0; `SPEC.md` is CC-BY-4.0;
  `ee/` has its own license and is not open to external contributions.
- Changes to `spec/schema` or `spec/vectors` require a `SPEC.md` update and a CHANGELOG entry.
- Keep comments to the non-obvious "why"; the code says "what".
