# Resolved 2026-10-21 from the golang:1.26.10-alpine manifest list digest on
# registry-1.docker.io (matches `docker pull golang:1.26.10-alpine && docker
# inspect --format='{{index .RepoDigests 0}}' golang:1.26.10-alpine`).
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

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
