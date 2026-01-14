.PHONY: help push release status test lint format install

help: ## Show this help message
	@echo "Faramesh Core - Quick Commands"
	@echo "=============================="
	@echo ""
	@echo "Usage: make <command>"
	@echo ""
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install package in development mode
	pip install -e ".[dev,test,cli]"

test: ## Run tests
	pytest

lint: ## Run linters (ruff, mypy)
	ruff check src/ tests/
	mypy src/faramesh --ignore-missing-imports || true

format: ## Format code with ruff
	ruff format src/ tests/

status: ## Show git status
	git status

push: ## Quick push (usage: make push MSG="your message")
	@if [ -z "$(MSG)" ]; then \
		echo "❌ Error: MSG required"; \
		echo "Usage: make push MSG=\"your commit message\""; \
		exit 1; \
	fi
	git add -A
	git commit -m "$(MSG)"
	git push origin $$(git branch --show-current)

release: ## Create release (usage: make release VERSION=0.2.1)
	@if [ -z "$(VERSION)" ]; then \
		echo "❌ Error: VERSION required"; \
		echo "Usage: make release VERSION=0.2.1"; \
		exit 1; \
	fi
	@./scripts/quick-release.sh $(VERSION) "Release v$(VERSION)"

clean: ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ .coverage htmlcov/

build: ## Build package
	python -m build

check: lint test ## Run all checks (lint + test)
