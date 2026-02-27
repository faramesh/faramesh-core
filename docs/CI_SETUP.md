# CI/CD Setup Guide

This document explains how to set up and use the CI/CD infrastructure for Faramesh Core.

## Overview

The CI/CD infrastructure includes:

- **Continuous Integration**: Automated testing, linting, and building on every PR
- **Automated Releases**: PyPI and Docker releases on version tags
- **Version Synchronization**: Tools to sync versions across repositories
- **Code Quality**: Coverage tracking, static analysis, and security scanning

## Workflows

### 1. CI Pipeline (`.github/workflows/ci.yml`)

Runs on every push and PR:

- **Lint & Type Check**: ruff, mypy
- **Tests**: pytest with coverage across Python 3.9-3.12
- **Build**: Package wheel and sdist
- **Docker**: Build Docker image (test only, no push)

### 2. Release Pipeline (`.github/workflows/release.yml`)

Triggers on version tags (e.g., `v0.2.1`):

1. **Build UI**: Checks out `faramesh-ui` repo, builds assets, copies to core
2. **Build Package**: Creates Python wheel with UI assets included
3. **Publish PyPI**: Uploads to PyPI using trusted publishing
4. **Docker**: Builds and pushes to `ghcr.io/faramesh/faramesh-core`
5. **GitHub Release**: Creates release with changelog and artifacts

### 3. Version Sync (`.github/workflows/version-sync.yml`)

Manual workflow to sync versions across repos:

- Updates `faramesh-python-sdk` version
- Updates `faramesh-node-sdk` version
- Creates PRs in each repo

## Setup Instructions

### 1. PyPI Trusted Publishing

PyPI now supports trusted publishing (no API tokens needed):

1. Go to https://pypi.org/manage/account/publishing/
2. Add a new "pending publisher"
3. Owner: `faramesh`
4. Repository: `faramesh-core`
5. Workflow filename: `.github/workflows/release.yml`
6. Environment name: `pypi` (must match workflow)

The workflow uses `pypa/gh-action-pypi-publish@release/v1` which automatically uses trusted publishing.

### 2. Codecov Setup

1. Sign up at https://codecov.io (use GitHub login)
2. Add `faramesh-core` repository
3. Copy the upload token (or use public repos - no token needed)
4. Add to GitHub Secrets as `CODECOV_TOKEN` (optional for public repos)

The CI workflow automatically uploads coverage reports.

### 3. GitHub Container Registry

Docker images are automatically pushed to `ghcr.io/faramesh/faramesh-core`.

To make images public:
1. Go to https://github.com/faramesh/faramesh-core/pkgs/container/faramesh-core
2. Click "Package settings"
3. Change visibility to "Public"

### 4. Update CODEOWNERS

Edit `.github/CODEOWNERS` with actual GitHub usernames or teams:

```
* @your-username
/src/faramesh/server/ @your-team
```

### 5. Update MAINTAINERS.md

Edit `MAINTAINERS.md` with actual maintainer information.

## Release Process

### Creating a Release

1. **Update version** in `pyproject.toml` and `src/faramesh/__init__.py`:
   ```bash
   # Update version to 0.2.1
   sed -i 's/version = "0.2.0"/version = "0.2.1"/' pyproject.toml
   sed -i 's/__version__ = "0.2.0"/__version__ = "0.2.1"/' src/faramesh/__init__.py
   ```

2. **Update CHANGELOG.md** with release notes

3. **Commit and tag**:
   ```bash
   git add pyproject.toml src/faramesh/__init__.py CHANGELOG.md
   git commit -m "chore: bump version to 0.2.1"
   git tag v0.2.1
   git push origin main
   git push origin v0.2.1
   ```

4. **Release workflow runs automatically**:
   - Builds UI from `faramesh-ui` repo
   - Builds Python package
   - Publishes to PyPI
   - Builds and pushes Docker image
   - Creates GitHub release

### Syncing Versions Across Repos

Use the version sync workflow:

1. Go to Actions → "Version Sync"
2. Click "Run workflow"
3. Enter version (e.g., `0.2.1`)
4. Select repos to update (e.g., `python-sdk,node-sdk`)
5. Workflow creates PRs in each repo

## Testing Workflows Locally

### Using act (GitHub Actions locally)

```bash
# Install act
brew install act  # macOS
# or: https://github.com/nektos/act

# Run CI workflow
act push

# Run release workflow (dry-run)
act workflow_dispatch -W .github/workflows/release.yml
```

## Troubleshooting

### PyPI Upload Fails

- Check PyPI trusted publishing is set up correctly
- Verify workflow has `id-token: write` permission
- Check PyPI account has package ownership

### Docker Build Fails

- Verify `Dockerfile` is in repo root
- Check `.dockerignore` isn't excluding needed files
- Ensure UI assets are built before Docker build

### Version Sync Fails

- Verify `GITHUB_TOKEN` has repo access
- Check target repos exist and are accessible
- Ensure branch protection allows PRs from workflow

### Coverage Not Uploading

- Codecov token is optional for public repos
- Check workflow has correct file paths
- Verify `pytest-cov` is installed

## Best Practices

1. **Always test locally** before pushing
2. **Use semantic versioning** (MAJOR.MINOR.PATCH)
3. **Update CHANGELOG.md** with every release
4. **Keep dependencies updated** (Dependabot helps)
5. **Review CI failures** before merging PRs
6. **Tag releases** with `v` prefix (e.g., `v0.2.1`)

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
- [Docker Buildx](https://docs.docker.com/build/buildx/)
- [Codecov Documentation](https://docs.codecov.com/)
