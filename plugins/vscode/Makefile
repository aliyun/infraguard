# Makefile for VS Code extension (InfraGuard)

ROOT_DIR ?= $(shell cd ../.. && pwd)

ALL_PLATFORMS := linux-x64 darwin-x64 darwin-arm64 win32-x64
GOBUILD := go build
LDFLAGS := -s -w
MAIN_PATH := ./cmd/infraguard

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
  CURRENT_OS := linux
else ifeq ($(UNAME_S),Darwin)
  CURRENT_OS := darwin
else
  CURRENT_OS := win32
endif

ifeq ($(UNAME_M),arm64)
  CURRENT_ARCH := arm64
else ifeq ($(UNAME_M),aarch64)
  CURRENT_ARCH := arm64
else
  CURRENT_ARCH := x64
endif

CURRENT_PLATFORM := $(CURRENT_OS)-$(CURRENT_ARCH)

.DEFAULT_GOAL := help

.PHONY: install build build-all clean help

install: ## Install dependencies
	npm install

define do_build_platform
	@mkdir -p build
	@platform=$(1); \
	echo "Building for $$platform..."; \
	os=$$(echo $$platform | cut -d'-' -f1); \
	arch=$$(echo $$platform | cut -d'-' -f2); \
	goarch=$$arch; \
	goos=$$os; \
	ext=""; \
	if [ "$$os" = "win32" ]; then goos="windows"; ext=".exe"; fi; \
	if [ "$$arch" = "x64" ]; then goarch="amd64"; fi; \
	(cd $(ROOT_DIR) && GOOS=$$goos GOARCH=$$goarch $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CURDIR)/bin/infraguard$$ext $(MAIN_PATH)) && \
	yes | npx --yes vsce package --target $$platform --no-git-tag-version 2>/dev/null && mv -f *-$$platform-*.vsix build/ || true
endef

build: ## Build extension for current platform only
	$(call do_build_platform,$(CURRENT_PLATFORM))

build-all: ## Build extension for all platforms
	@for platform in $(ALL_PLATFORMS); do \
		echo "Building for $$platform..."; \
		os=$$(echo $$platform | cut -d'-' -f1); \
		arch=$$(echo $$platform | cut -d'-' -f2); \
		goarch=$$arch; \
		goos=$$os; \
		ext=""; \
		if [ "$$os" = "win32" ]; then goos="windows"; ext=".exe"; fi; \
		if [ "$$arch" = "x64" ]; then goarch="amd64"; fi; \
		(cd $(ROOT_DIR) && GOOS=$$goos GOARCH=$$goarch $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CURDIR)/bin/infraguard$$ext $(MAIN_PATH)) && \
		yes | npx --yes vsce package --target $$platform --no-git-tag-version 2>/dev/null && mv -f *-$$platform-*.vsix build/ || true; \
	done

clean: ## Clean build artifacts
	rm -rf build/ bin/ out/

help: ## Show this help
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
