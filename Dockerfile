# Resolved 2026-09-01 from the golang:1.26.6-alpine manifest list digest on
# registry-1.docker.io (matches `docker pull golang:1.26.6-alpine && docker
# inspect --format='{{index .RepoDigests 0}}' golang:1.26.6-alpine`).
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /mctl-api ./cmd/api

FROM alpine:3.24

RUN apk add --no-cache ca-certificates git openssh-client

RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app

COPY --from=builder /mctl-api /usr/local/bin/mctl-api

USER app:app

# Default: run the API server.
ENTRYPOINT ["mctl-api"]
