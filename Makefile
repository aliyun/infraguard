# Makefile for infraguard

# Binary name
BINARY_NAME := infraguard

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GORUN := $(GOCMD) run
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet

# Documentation parameters
DOCS_DIR := docs
NPM := npm

# Build flags
LDFLAGS := -s -w
BUILD_DIR := .
MAIN_PATH := ./cmd/infraguard

# Default target
.DEFAULT_GOAL := help

.PHONY: all build run clean test test-policy test-all test-web test-coverage format lint tidy deps help install doc-gen doc-dev doc-serve doc-build doc-clean

## Build targets

all: clean gen-policy build ## Clean and build the binary

gen-policy: ## Generate policy index
	$(GORUN) cmd/policy-gen/main.go
	$(GOFMT) pkg/policy/index_gen.go

build: gen-policy ## Build the binary
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

run: ## Run the application
	$(GORUN) $(MAIN_PATH)

## Test targets

test: ## Run tests for pkg/ and cmd/ packages
	$(GOTEST) -v ./pkg/... ./cmd/...

test-policy: gen-policy  ## Run tests for policies/ directory
	$(GOTEST) -v ./policies/...

test-all: ## Run both test and test-policy concurrently
	@$(MAKE) -j2 test test-policy

test-web: ## Run tests with GoConvey web UI (pkg/ and cmd/)
	@if ! command -v goconvey >/dev/null 2>&1; then \
		echo "Installing goconvey..."; \
		$(GOCMD) install github.com/smartystreets/goconvey@latest; \
	fi
	@echo "Starting GoConvey web UI at http://localhost:8080"
	@echo "Note: GoConvey will test all packages. Use browser filters to focus on specific packages."
	goconvey

test-coverage: ## Run tests with coverage for pkg/ and cmd/ and open report
	$(GOTEST) -v -coverprofile=coverage.out ./pkg/... ./cmd/...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@if command -v open >/dev/null 2>&1; then \
		open coverage.html; \
	elif command -v xdg-open >/dev/null 2>&1; then \
		xdg-open coverage.html; \
	elif command -v start >/dev/null 2>&1; then \
		start coverage.html; \
	else \
		echo "Please open coverage.html manually in your browser"; \
	fi

## Code quality targets

check-gen: ## Check if generated files are up to date
	@echo "Checking if index_gen.go is up to date..."
	@cp pkg/policy/index_gen.go pkg/policy/index_gen.go.bak 2>/dev/null || true
	@$(GORUN) cmd/policy-gen/main.go
	@$(GOFMT) pkg/policy/index_gen.go >/dev/null
	@if ! diff -q pkg/policy/index_gen.go pkg/policy/index_gen.go.bak >/dev/null 2>&1; then \
		echo "ERROR: pkg/policy/index_gen.go is out of date!"; \
		echo "Please run 'make gen-policy' and commit the changes."; \
		mv pkg/policy/index_gen.go.bak pkg/policy/index_gen.go 2>/dev/null || true; \
		exit 1; \
	fi
	@rm -f pkg/policy/index_gen.go.bak
	@echo "✓ pkg/policy/index_gen.go is up to date"

format: ## Format code
	$(GOFMT) ./...

lint: ## Run go vet
	$(GOVET) ./...

## Dependency targets

deps: ## Download dependencies
	$(GOMOD) download

tidy: ## Tidy go modules
	$(GOMOD) tidy

vendor: ## Vendor dependencies
	$(GOMOD) vendor

## Clean targets

clean: ## Clean build artifacts
	rm -f $(BUILD_DIR)/$(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -rf vendor/
	rm -rf pkg/policy/index_gen.go
	rm -rf $(DOCS_DIR)/build
	rm -rf $(DOCS_DIR)/.docusaurus
	rm -rf $(DOCS_DIR)/docs/policies
	rm -rf $(DOCS_DIR)/i18n/zh/docusaurus-plugin-content-docs/current/policies
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[co]" -delete

## Install targets

install: ## Install development dependencies (Node.js packages for documentation)
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Error: Node.js is not installed. Please install Node.js first."; \
		exit 1; \
	fi
	@echo "Installing documentation dependencies..."
	cd $(DOCS_DIR) && $(NPM) install

## Documentation targets

doc-gen: ## Generate policy documentation from .rego files
	@echo "Generating policy documentation..."
	$(GORUN) scripts/generate-policy-docs.go

doc-dev: doc-gen ## Start documentation development server (hot reload)
	@echo "Starting documentation development server..."
	cd $(DOCS_DIR) && $(NPM) start

doc-serve: doc-build ## Serve the production build locally (supports multiple locales)
	@echo "Serving production build..."
	cd $(DOCS_DIR) && $(NPM) run serve

doc-build: doc-gen ## Build static documentation site
	@echo "Building documentation site..."
	cd $(DOCS_DIR) && $(NPM) run build

## Help target

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

