# Makefile for infraguard

BINARY_NAME := infraguard
GOCMD := go
NPM := npm
LDFLAGS := -s -w
MAIN_PATH := ./cmd/infraguard

.DEFAULT_GOAL := help
.PHONY: build cli-build run doc-build doc-serve test test-coverage test-policy lint fmt validate-translations check-gen gen-policy sync-scenario-packs clean help

## Build

gen-policy: ## Generate the policy index
	$(GOCMD) run cmd/policy-gen/main.go
	$(GOCMD) fmt pkg/policy/index_gen.go

sync-scenario-packs: ## Sync top-level scenario packs with their directory rule roll-ups
	$(GOCMD) run scripts/sync-scenario-packs.go

build: gen-policy ## Build everything (web UI + binary)
	cd web && $(NPM) ci && $(NPM) run build
	@touch pkg/server/dist/.gitkeep
	$(GOCMD) build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) $(MAIN_PATH)

cli-build: gen-policy ## Build CLI binary only
	$(GOCMD) build -ldflags "$(LDFLAGS)" -o "$(CURDIR)/$(BINARY_NAME)" $(MAIN_PATH)

run: ## Run from source
	$(GOCMD) run $(MAIN_PATH)

doc-build: ## Build the documentation site (incl. wasm playground)
	$(GOCMD) run scripts/generate-policy-docs.go
	@mkdir -p docs/static/playground
	GOOS=js GOARCH=wasm $(GOCMD) build -o docs/static/playground/infraguard.wasm ./cmd/infraguard-wasm
	cp "$$($(GOCMD) env GOROOT)/lib/wasm/wasm_exec.js" docs/static/playground/wasm_exec.js
	$(GOCMD) run ./cmd/policy-dump -pack quick-start-compliance-pack -out docs/static/playground/rules.json
	cd docs && $(NPM) ci && $(NPM) run build

doc-serve: doc-build ## Serve the documentation site locally
	cd docs && $(NPM) run serve

## Test & quality

test: gen-policy ## Run all tests
	$(GOCMD) test ./pkg/... ./cmd/... ./policies/...

test-coverage: gen-policy ## Check total Go statement coverage is at least 95%
	@set -e; workdir=$$(mktemp -d); trap 'rm -rf "$$workdir"' EXIT; \
	all_packages=$$($(GOCMD) list ./pkg/... ./cmd/... ./policies/...); \
	packages=$$(printf '%s\n' "$$all_packages" | awk '$$0 !~ /\/cmd\/policy-dump$$/'); \
	coverpkg=$$(printf '%s\n' "$$packages" | paste -sd, -); \
	$(GOCMD) test -timeout=30m -coverpkg="$$coverpkg" -coverprofile="$$workdir/all.out" $$packages; \
	for script in scripts/*.go; do \
		case "$$script" in *_test.go|scripts/generate-policy-docs.go|scripts/validate-doc-translations.go) continue;; esac; \
		set -- "$$script"; testfile="$${script%.go}_test.go"; \
		if [ -f "$$testfile" ]; then set -- "$$script" "$$testfile"; fi; \
		$(GOCMD) test -timeout=30m -coverprofile="$$workdir/script.out" "$$@"; \
		tail -n +2 "$$workdir/script.out" >> "$$workdir/all.out"; \
	done; \
	awk 'NR > 1 { statements[$$1] = $$2; if ($$3 > 0) hit[$$1] = 1 } END { for (block in statements) { total += statements[block]; if (hit[block]) covered += statements[block] } if (total == 0) { print "No coverage data"; exit 1 } printf "Total statement coverage: %.2f%% (%d/%d)\n", 100 * covered / total, covered, total; if (covered / total < 0.95) { print "Coverage is below 95%"; exit 1 } }' "$$workdir/all.out"

test-policy: gen-policy ## Run policy tests only
	$(GOCMD) test ./policies/...

validate-translations: ## Validate translation files
	$(GOCMD) run scripts/validate-translations.go

lint: ## Run go vet
	$(GOCMD) vet ./pkg/... ./cmd/... ./policies/...

fmt: ## Format Go code
	$(GOCMD) fmt ./...

check-gen: ## Verify the generated policy index is up to date
	@cp pkg/policy/index_gen.go pkg/policy/index_gen.go.bak
	@$(GOCMD) run cmd/policy-gen/main.go && $(GOCMD) fmt pkg/policy/index_gen.go >/dev/null
	@diff -q pkg/policy/index_gen.go pkg/policy/index_gen.go.bak >/dev/null \
		|| { echo "index_gen.go is out of date; run 'make gen-policy'"; mv pkg/policy/index_gen.go.bak pkg/policy/index_gen.go; exit 1; }
	@rm -f pkg/policy/index_gen.go.bak
	@echo "index_gen.go is up to date"

## Clean

clean: ## Remove build artifacts
	rm -f $(BINARY_NAME) coverage.out coverage.html
	rm -rf pkg/server/dist/assets pkg/server/dist/index.html
	rm -rf docs/build docs/.docusaurus docs/static/playground

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
