#!/bin/bash
# Quick release script for Faramesh Core
# Usage: ./scripts/quick-release.sh 0.2.1 "Release notes"

set -e

VERSION="${1}"
NOTES="${2:-Release v$VERSION}"

if [ -z "$VERSION" ]; then
    echo "❌ Error: Version required"
    echo "Usage: ./scripts/quick-release.sh 0.2.1 \"Release notes\""
    exit 1
fi

echo "🚀 Quick Release for Faramesh Core"
echo "==================================="
echo "Version: $VERSION"
echo "Notes: $NOTES"
echo ""

# Check if we're in a git repo
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Error: Not in a git repository"
    exit 1
fi

# Check if on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "master" ]; then
    echo "⚠️  Warning: Not on main/master branch (currently on $BRANCH)"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "⚠️  Warning: You have uncommitted changes"
    git status --short
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update version in pyproject.toml
if [ -f "pyproject.toml" ]; then
    echo "📝 Updating pyproject.toml..."
    sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" pyproject.toml
    rm -f pyproject.toml.bak
fi

# Update version in __init__.py
if [ -f "src/faramesh/__init__.py" ]; then
    echo "📝 Updating __init__.py..."
    sed -i.bak "s/^__version__ = \".*\"/__version__ = \"$VERSION\"/" src/faramesh/__init__.py
    rm -f src/faramesh/__init__.py.bak
fi

# Show changes
echo ""
echo "📊 Version changes:"
git diff pyproject.toml src/faramesh/__init__.py || true
echo ""

# Confirm
read -p "Create release commit and tag? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 1
fi

# Commit version changes
echo "💾 Committing version changes..."
git add pyproject.toml src/faramesh/__init__.py
git commit -m "chore: bump version to $VERSION"

# Create tag
echo "🏷️  Creating tag v$VERSION..."
git tag -a "v$VERSION" -m "$NOTES"

# Push
echo "📤 Pushing to origin..."
git push origin "$BRANCH"
git push origin "v$VERSION"

echo ""
echo "✅ Release created!"
echo "   Version: $VERSION"
echo "   Tag: v$VERSION"
echo "   Branch: $BRANCH"
echo ""
echo "⏳ GitHub Actions will now:"
echo "   1. Build UI from faramesh-ui repo"
echo "   2. Build Python package"
echo "   3. Publish to PyPI"
echo "   4. Build Docker image"
echo "   5. Create GitHub release"
echo ""
echo "📊 View workflow: https://github.com/faramesh/faramesh-core/actions"
