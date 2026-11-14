VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build build-api build-mcp run run-mcp test clean fmt

build: build-api build-mcp

build-api:
	go build $(LDFLAGS) -o bin/mctl-api ./cmd/api

build-mcp:
	go build $(LDFLAGS) -o bin/mctl-mcp ./cmd/mcp

run: build-api
	GITOPS_LOCAL_PATH=../mctl-gitops bin/mctl-api

run-mcp: build-mcp
	MCTL_API_URL=http://localhost:8080 bin/mctl-mcp

# -p 1: the Postgres-backed tests of several packages share one
# TEST_DATABASE_URL and wipe tables in setup/cleanup, so package test
# binaries must not run in parallel (same reason as validate.yml).
test:
	go test -p 1 ./... -v

clean:
	rm -rf bin/

fmt:
	go fmt ./...
	goimports -w .
