# SDK Repositories CI/CD Setup Guide

This guide explains how to set up CI/CD for the separate SDK repositories.

## Overview

Faramesh has multiple repositories:
- `faramesh-core` - Main server (already has CI/CD)
- `faramesh-python-sdk` - Python SDK
- `faramesh-node-sdk` - Node.js SDK
- `faramesh-ui` - Web UI
- `faramesh-docs` - Documentation
- `faramesh-examples` - Examples

## Quick Setup

### 1. Generate Workflow Templates

Run the setup script from `faramesh-core`:

```bash
cd ~/projects/faramesh-core
./scripts/setup-sdk-repos.sh
```

This creates workflow templates in `.github/workflows-templates/`.

### 2. Copy Workflows to SDK Repos

#### Python SDK

```bash
# Create workflows directory
mkdir -p ~/projects/faramesh-python-sdk/.github/workflows

# Copy CI workflow
cp ~/projects/faramesh-core/.github/workflows-templates/python-sdk-ci.yml \
   ~/projects/faramesh-python-sdk/.github/workflows/ci.yml

# Copy release workflow
cp ~/projects/faramesh-core/.github/workflows-templates/python-sdk-release.yml \
   ~/projects/faramesh-python-sdk/.github/workflows/release.yml
```

#### Node SDK

```bash
# Create workflows directory
mkdir -p ~/projects/faramesh-node-sdk/.github/workflows

# Copy CI workflow
cp ~/projects/faramesh-core/.github/workflows-templates/node-sdk-ci.yml \
   ~/projects/faramesh-node-sdk/.github/workflows/ci.yml

# Copy release workflow
cp ~/projects/faramesh-core/.github/workflows-templates/node-sdk-release.yml \
   ~/projects/faramesh-node-sdk/.github/workflows/release.yml
```

#### UI

```bash
# Create workflows directory
mkdir -p ~/projects/faramesh-ui/.github/workflows

# Copy CI workflow
cp ~/projects/faramesh-core/.github/workflows-templates/ui-ci.yml \
   ~/projects/faramesh-ui/.github/workflows/ci.yml
```

### 3. Set Up PyPI Trusted Publishing (Python SDK)

1. Go to https://pypi.org/manage/account/publishing/
2. Add new "pending publisher":
   - Owner: `faramesh`
   - Repository: `faramesh-python-sdk`
   - Workflow filename: `.github/workflows/release.yml`
   - Environment name: `pypi`

### 4. Set Up npm Token (Node SDK)

1. Get npm token:
   ```bash
   npm login
   npm token create
   ```

2. Add to GitHub Secrets:
   - Go to https://github.com/faramesh/faramesh-node-sdk/settings/secrets/actions
   - Add secret: `NPM_TOKEN` with your npm token

### 5. Commit and Push

```bash
# In each SDK repo
git add .github/workflows/
git commit -m "ci: add CI/CD workflows"
git push origin main
```

## Workflow Details

### Python SDK CI

Runs on every push and PR:
- Tests on Python 3.9, 3.10, 3.11, 3.12
- Runs pytest
- Runs mypy (type checking)
- Runs ruff (linting)
- Builds package wheel

### Python SDK Release

Triggers on version tags (e.g., `v0.2.1`):
- Builds wheel and sdist
- Publishes to PyPI using trusted publishing
- No API token needed!

### Node SDK CI

Runs on every push and PR:
- Tests on Node.js 18, 20, 22
- Runs npm test
- Builds package
- Type checks with TypeScript
- Lints (if configured)

### Node SDK Release

Triggers on version tags (e.g., `v0.2.1`):
- Runs tests
- Builds package
- Publishes to npm
- Requires `NPM_TOKEN` secret

### UI CI

Runs on every push and PR:
- Installs dependencies
- Lints (if configured)
- Type checks
- Builds production bundle
- Uploads artifacts

## Version Synchronization

The `faramesh-core` repository has a version sync workflow that automatically creates PRs in SDK repos when you release a new version.

### Automatic Sync

When you create a release in `faramesh-core`:
1. Release workflow completes
2. Version sync workflow triggers automatically
3. Creates PRs in `python-sdk` and `node-sdk` repos
4. You review and merge the PRs

### Manual Sync

You can also trigger version sync manually:

1. Go to Actions → "Version Sync"
2. Click "Run workflow"
3. Enter version (e.g., `0.2.1`)
4. Select repos to update
5. Workflow creates PRs

## Release Process

### Python SDK

```bash
cd ~/projects/faramesh-python-sdk

# Update version
sed -i 's/version = "0.2.0"/version = "0.2.1"/' pyproject.toml
sed -i 's/__version__ = "0.2.0"/__version__ = "0.2.1"/' faramesh/__init__.py

# Commit and tag
git add pyproject.toml faramesh/__init__.py
git commit -m "chore: bump version to 0.2.1"
git tag v0.2.1
git push origin main
git push origin v0.2.1

# Release workflow runs automatically
```

### Node SDK

```bash
cd ~/projects/faramesh-node-sdk

# Update version
npm version 0.2.1 --no-git-tag-version

# Commit and tag
git add package.json package-lock.json
git commit -m "chore: bump version to 0.2.1"
git tag v0.2.1
git push origin main
git push origin v0.2.1

# Release workflow runs automatically
```

## Troubleshooting

### PyPI Upload Fails

- Check PyPI trusted publishing is set up correctly
- Verify workflow has `id-token: write` permission
- Check PyPI account has package ownership

### npm Publish Fails

- Verify `NPM_TOKEN` secret is set correctly
- Check npm package name is available
- Ensure package.json has correct name and version

### Version Sync Fails

- Verify `GITHUB_TOKEN` has repo access
- Check target repos exist and are accessible
- Ensure branch protection allows PRs from workflow

## Best Practices

1. **Always test locally** before pushing
2. **Use semantic versioning** (MAJOR.MINOR.PATCH)
3. **Update CHANGELOG.md** with every release
4. **Keep dependencies updated** (Dependabot helps)
5. **Review CI failures** before merging PRs
6. **Tag releases** with `v` prefix (e.g., `v0.2.1`)
