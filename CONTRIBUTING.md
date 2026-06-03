# Contributing

Thanks for contributing to `agent-signing`! This guide covers the local
development workflow -- linting, testing, and cutting a release. All tooling is
driven by [`uv`](https://docs.astral.sh/uv/) and mirrors what runs in CI.

## Setup

Install `uv` (see the [install guide](https://docs.astral.sh/uv/getting-started/installation/)),
then sync the project with its development dependencies:

```bash
uv sync --extra dev
```

This creates a virtual environment and installs `pytest`, `ruff`, and the
runtime dependencies.

## Lint

We use [`ruff`](https://docs.astral.sh/ruff/) for both linting and formatting.
The CI `Lint and Test` workflow runs the same two checks:

```bash
uvx ruff check agent_signing/ tests/          # lint
uvx ruff format --check agent_signing/ tests/  # formatting check (no changes)
```

To auto-fix issues and format the code locally before committing:

```bash
uvx ruff check --fix agent_signing/ tests/
uvx ruff format agent_signing/ tests/
```

## Test

Run the test suite with `pytest`:

```bash
uv run pytest
```

CI runs the tests against Python 3.11, 3.12, and 3.13. To check a specific
version locally:

```bash
uv run --python 3.11 pytest
```

## Commit messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/),
which is what [commitizen](https://commitizen-tools.github.io/commitizen/) uses
to determine the next version. Prefix each commit with a type, e.g.:

```
feat: add Ed25519 key rotation
fix: handle empty manifest gracefully
docs: clarify HMAC signing example
ci: pin action SHAs
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`,
`perf`. A `feat` triggers a minor bump, a `fix` a patch bump, and a `!` or
`BREAKING CHANGE:` footer a major bump. You can craft a compliant message
interactively with:

```bash
uvx --from commitizen cz commit
```

## Release

Releases are tag-driven. commitizen computes the new version from the
Conventional Commits since the last tag, and pushing the tag drives CI to
publish to PyPI.

1. Make sure `main` is up to date and the working tree is clean.
2. Bump the version locally with commitizen. This updates the version in
   `pyproject.toml`, regenerates `CHANGELOG.md`, commits the change, and
   creates a `vX.Y.Z` tag:

   ```bash
   uvx --from commitizen cz bump
   ```

   Preview what would happen without making changes:

   ```bash
   uvx --from commitizen cz bump --dry-run
   ```

3. Push the bump commit together with the new tag:

   ```bash
   git push --follow-tags
   ```

From there CI takes over:

- The **`Release on tag`** workflow (`.github/workflows/bump.yml`) runs on the
  `v*` tag, extracts the changelog section for that version, and creates a
  GitHub Release.
- The **`Release to PyPI`** workflow (`.github/workflows/release.yml`) runs when
  that Release is published, builds the sdist and wheel with `uv build`, and
  uploads them to PyPI via Trusted Publishing.

### Release prerequisites (one-time)

- **PyPI Trusted Publishing** -- configure a trusted publisher for the project
  pointing at `release.yml` and the `pypi` environment. See the
  [PyPI docs](https://docs.pypi.org/trusted-publishers/). (Alternatively set a
  `PYPI_API_TOKEN` secret and pass it as `password` to the publish step.)
- **GitHub App** -- so the Release created by CI triggers the PyPI publish
  (Releases created with the default `GITHUB_TOKEN` do not start new workflow
  runs). Create a GitHub App with `Contents: read & write`, install it on this
  repo, then store its App ID as the `CZ_APP_ID` repository variable and its
  private key as the `CZ_APP_PRIVATE_KEY` secret.
