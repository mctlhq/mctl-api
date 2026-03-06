FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build both binaries.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mctl-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mctl-mcp ./cmd/mcp

FROM alpine:3.20

RUN apk add --no-cache ca-certificates git

COPY --from=builder /mctl-api /usr/local/bin/mctl-api
COPY --from=builder /mctl-mcp /usr/local/bin/mctl-mcp

# Default: run the API server.
ENTRYPOINT ["mctl-api"]
