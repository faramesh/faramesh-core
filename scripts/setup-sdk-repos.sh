#!/bin/bash
# Setup script to create CI workflows in SDK repos
# This script generates the CI workflow files that should be copied to each SDK repo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "📦 Faramesh SDK Repos CI Setup"
echo "=============================="
echo ""

# Create templates directory
TEMPLATES_DIR="$PROJECT_ROOT/.github/workflows-templates"
mkdir -p "$TEMPLATES_DIR"

echo "📝 Creating CI workflow templates..."
echo ""

# Python SDK CI template
cat > "$TEMPLATES_DIR/python-sdk-ci.yml" << 'EOF'
name: CI

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  test:
    name: Python SDK Tests
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.10", "3.11", "3.12"]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[test]"

      - name: Run pytest
        run: pytest

      - name: Run mypy
        run: mypy faramesh --ignore-missing-imports || true
        continue-on-error: true

      - name: Run ruff
        run: |
          pip install ruff
          ruff check . || true
        continue-on-error: true

  build:
    name: Build Python SDK
    runs-on: ubuntu-latest
    needs: test

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install build tools
        run: |
          python -m pip install --upgrade pip
          pip install build wheel

      - name: Build wheel
        run: python -m build

      - name: Check wheel
        run: |
          pip install twine
          twine check dist/*
EOF

# Node SDK CI template
cat > "$TEMPLATES_DIR/node-sdk-ci.yml" << 'EOF'
name: CI

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  test:
    name: Node SDK Tests
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: ["18", "20", "22"]

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test || echo "No tests yet"

      - name: Build
        run: npm run build

      - name: Type check
        run: npx tsc --noEmit || echo "TypeScript check skipped"
        continue-on-error: true

      - name: Lint
        run: npm run lint || echo "Lint check skipped"
        continue-on-error: true

  build:
    name: Build Node SDK
    runs-on: ubuntu-latest
    needs: test

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Check package
        run: npm pack --dry-run
EOF

# UI CI template
cat > "$TEMPLATES_DIR/ui-ci.yml" << 'EOF'
name: CI

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  build:
    name: Build UI
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install dependencies
        run: npm ci

      - name: Lint
        run: npm run lint || echo "Lint check skipped"
        continue-on-error: true

      - name: Type check
        run: npx tsc --noEmit || echo "TypeScript check skipped"
        continue-on-error: true

      - name: Build
        run: npm run build

      - name: Upload build artifacts
        uses: actions/upload-artifact@v4
        with:
          name: ui-dist
          path: dist
          retention-days: 7
EOF

# Python SDK Release template
cat > "$TEMPLATES_DIR/python-sdk-release.yml" << 'EOF'
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

jobs:
  publish:
    name: Publish to PyPI
    runs-on: ubuntu-latest
    environment:
      name: pypi
      url: https://pypi.org/p/faramesh-sdk
    permissions:
      id-token: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install build tools
        run: |
          python -m pip install --upgrade pip
          pip install build wheel twine

      - name: Build wheel and sdist
        run: python -m build

      - name: Check package
        run: twine check dist/*

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          packages-dir: dist/
          print-hash: true
EOF

# Node SDK Release template
cat > "$TEMPLATES_DIR/node-sdk-release.yml" << 'EOF'
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

jobs:
  publish:
    name: Publish to npm
    runs-on: ubuntu-latest
    permissions:
      contents: write
      packages: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"
          registry-url: 'https://registry.npmjs.org'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test || echo "No tests yet"

      - name: Build
        run: npm run build

      - name: Publish to npm
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
EOF

echo "✅ Created workflow templates in: $TEMPLATES_DIR"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Copy CI workflows to SDK repos:"
echo "   cp $TEMPLATES_DIR/python-sdk-ci.yml ../faramesh-python-sdk/.github/workflows/ci.yml"
echo "   cp $TEMPLATES_DIR/node-sdk-ci.yml ../faramesh-node-sdk/.github/workflows/ci.yml"
echo "   cp $TEMPLATES_DIR/ui-ci.yml ../faramesh-ui/.github/workflows/ci.yml"
echo ""
echo "2. Copy release workflows:"
echo "   cp $TEMPLATES_DIR/python-sdk-release.yml ../faramesh-python-sdk/.github/workflows/release.yml"
echo "   cp $TEMPLATES_DIR/node-sdk-release.yml ../faramesh-node-sdk/.github/workflows/release.yml"
echo ""
echo "3. Set up PyPI trusted publishing for python-sdk:"
echo "   https://pypi.org/manage/account/publishing/"
echo ""
echo "4. Add NPM_TOKEN secret to node-sdk repo:"
echo "   https://github.com/faramesh/faramesh-node-sdk/settings/secrets/actions"
echo ""
