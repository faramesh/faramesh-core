# Quick Start Guide - Git Operations in Cursor

This guide shows you the easiest ways to commit, push, and release in Cursor.

## 🚀 Quick Push (Easiest)

### Option 1: Using the Script (Recommended)
```bash
./scripts/quick-push.sh "your commit message"
```

### Option 2: Using Make
```bash
make push MSG="your commit message"
```

### Option 3: Using Git Aliases
First, add aliases to your git config:
```bash
git config --global include.path ~/projects/faramesh-core/.gitconfig.local
```

Then use:
```bash
git ac "your commit message"
git p  # push
```

Or combine:
```bash
git acp "your commit message"
```

## 🏷️ Quick Release

### Option 1: Using the Script (Recommended)
```bash
./scripts/quick-release.sh 0.2.1 "Release notes here"
```

### Option 2: Using Make
```bash
make release VERSION=0.2.1
```

### Option 3: Using Git Alias
```bash
git release 0.2.1
```

## 📋 Common Workflows

### Daily Development
```bash
# Make changes in Cursor...

# Quick push
./scripts/quick-push.sh "feat: add new feature"
```

### Creating a Release
```bash
# Update version and create release
./scripts/quick-release.sh 0.2.1 "Added new features and bug fixes"

# GitHub Actions will automatically:
# - Build UI from faramesh-ui repo
# - Build Python package
# - Publish to PyPI
# - Build Docker image
# - Create GitHub release
```

### Check Status
```bash
make status
# or
git status
```

### Run Tests Before Pushing
```bash
make test
make lint
./scripts/quick-push.sh "fix: update tests"
```

## 🎯 Cursor-Specific Tips

### 1. Use Cursor's Built-in Terminal
- Press `` Ctrl+` `` (backtick) to open terminal
- Or use `View > Terminal` menu

### 2. Use Cursor's Source Control Panel
- Click the Source Control icon in sidebar (or `Ctrl+Shift+G`)
- Stage files by clicking `+` next to files
- Type commit message in the box
- Click `✓` to commit
- Click `...` menu → `Push` to push

### 3. Keyboard Shortcuts
- `Ctrl+Shift+G` - Open Source Control
- `Ctrl+K Ctrl+H` - Toggle Source Control view
- `Ctrl+Enter` - Commit (when in Source Control panel)

### 4. Quick Commands in Terminal
Add to your `~/.bashrc` or `~/.zshrc`:
```bash
# Faramesh shortcuts
alias fp='cd ~/projects/faramesh-core && ./scripts/quick-push.sh'
alias fr='cd ~/projects/faramesh-core && ./scripts/quick-release.sh'
```

Then use:
```bash
fp "your message"
fr 0.2.1 "release notes"
```

## 📝 Example Workflow

```bash
# 1. Make changes in Cursor

# 2. Check what changed
make status

# 3. Run tests
make test

# 4. Quick push
./scripts/quick-push.sh "feat: add new integration"

# 5. When ready to release
./scripts/quick-release.sh 0.2.1 "New features and improvements"
```

## 🔧 Troubleshooting

### Scripts not executable
```bash
chmod +x scripts/*.sh
```

### Make not found
```bash
# macOS
brew install make

# Or use the scripts directly
./scripts/quick-push.sh "message"
```

### Git aliases not working
```bash
# Add to global config
git config --global include.path ~/projects/faramesh-core/.gitconfig.local

# Or add manually
git config --global alias.ac '!git add -A && git commit -m'
git config --global alias.p 'push origin'
```

## 💡 Pro Tips

1. **Use Cursor's AI**: Ask Cursor to write commit messages:
   - Select changed files
   - Ask: "Write a good commit message for these changes"

2. **Use Make for Everything**:
   ```bash
   make help        # See all commands
   make test        # Run tests
   make lint        # Check code
   make format      # Format code
   make push MSG="..."  # Quick push
   ```

3. **Combine Commands**:
   ```bash
   make test && make lint && ./scripts/quick-push.sh "all checks passed"
   ```

4. **Use Git Aliases Everywhere**:
   After adding the config, these work in any repo:
   ```bash
   git s      # short status
   git recent # recent commits
   git ac "message" && git p  # add, commit, push
   ```
