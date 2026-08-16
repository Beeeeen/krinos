# Krinos development tasks.
#
# Windows contributors without make can run the underlying `go` commands
# directly; every recipe here is a single command on purpose so that copying
# one out of this file always works.

BINARY  := krinos
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := check

.PHONY: build
build: ## Build the CLI into bin/
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/krinos

.PHONY: test
test: ## Run the test suite with the race detector
	go test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and print coverage per function
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: fmt
fmt: ## Format all Go source
	gofmt -w .

.PHONY: lint
lint: ## Verify formatting and run vet
	@test -z "$$(gofmt -l .)" || (echo "not gofmt-clean:"; gofmt -l .; exit 1)
	go vet ./...

.PHONY: deps
deps: ## Assert the zero-dependency invariant
	@deps="$$(go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | grep -v '^github.com/krinos-dev/krinos' || true)"; \
	if [ -n "$$deps" ]; then \
		echo "Krinos must have zero third-party dependencies. Found:"; echo "$$deps"; exit 1; \
	fi; \
	echo "confirmed: standard library only"

.PHONY: check
check: lint deps test ## Everything CI runs, locally

.PHONY: demo
demo: build ## Triage the bundled demo corpus
	./bin/$(BINARY) scan --fail-on never testdata/demo/

.PHONY: docker
docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t krinos:$(VERSION) .

.PHONY: clean
clean: ## Remove build output
	rm -rf bin coverage.out

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'
