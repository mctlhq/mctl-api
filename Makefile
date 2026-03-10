VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build build-api build-mcp run run-mcp test clean fmt

build: build-api build-mcp

build-api:
	go build $(LDFLAGS) -o bin/mctl-api ./cmd/api

build-mcp:
	go build $(LDFLAGS) -o bin/mctl-mcp ./cmd/mcp

run: build-api
	GITOPS_LOCAL_PATH=../mctl-core bin/mctl-api

run-mcp: build-mcp
	MCTL_API_URL=http://localhost:8080 bin/mctl-mcp

test:
	go test ./... -v

clean:
	rm -rf bin/

fmt:
	go fmt ./...
	goimports -w .
