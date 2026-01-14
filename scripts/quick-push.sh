#!/bin/bash
# Quick push script for Faramesh Core
# Usage: ./scripts/quick-push.sh "commit message"

set -e

COMMIT_MSG="${1:-Update}"

echo "🚀 Quick Push for Faramesh Core"
echo "================================"
echo ""

# Check if we're in a git repo
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Error: Not in a git repository"
    exit 1
fi

# Get current branch
BRANCH=$(git branch --show-current)
echo " branch: $BRANCH"
echo ""

# Show status
echo "📊 Current status:"
git status --short
echo ""

# Ask for confirmation
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 1
fi

# Add all changes
echo "➕ Staging all changes..."
git add -A

# Commit
echo "💾 Committing: $COMMIT_MSG"
git commit -m "$COMMIT_MSG"

# Push
echo "📤 Pushing to origin/$BRANCH..."
git push origin "$BRANCH"

echo ""
echo "✅ Done! Pushed to origin/$BRANCH"
echo ""

# Show recent commits
echo "📝 Recent commits:"
git log --oneline -3
