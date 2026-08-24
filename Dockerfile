# syntax=docker/dockerfile:1

# Build stage ---------------------------------------------------------------
FROM golang:1.26.6-alpine AS build

WORKDIR /src

# Dependencies first, so a code-only change reuses the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# CGO_ENABLED=0 keeps the binary static — the SQLite driver is pure Go, so
# there is nothing to link against and the runtime image can be scratch.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X github.com/jameshoulder/dnsdaddy/internal/version.Version=${VERSION}" \
        -o /out/dnsdaddy ./cmd/dnsdaddy

# The lab tools are built here but land only in the `lab` stage below, so the
# production image carries the resolver and nothing else.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" \
        -o /out/dnsdaddy-lab ./cmd/dnsdaddy-lab

# Lab stage -----------------------------------------------------------------
#
# A separate image, used only by `docker compose --profile lab`. It contains
# the traffic generator and the synthetic responder, which have no business
# being in the image that answers a real network's DNS.
FROM alpine:3.21 AS lab

RUN addgroup -g 10001 -S dnsdaddy \
    && adduser -u 10001 -S -G dnsdaddy dnsdaddy

COPY --from=build /out/dnsdaddy-lab /usr/local/bin/dnsdaddy-lab

USER dnsdaddy
ENTRYPOINT ["/usr/local/bin/dnsdaddy-lab"]

# Runtime stage -------------------------------------------------------------
#
# Deliberately last: Docker builds the final stage by default, so plain
# `docker build .` produces the resolver image and never the lab one.
FROM alpine:3.21 AS runtime

# ca-certificates for HTTPS feed downloads and DNS-over-TLS upstream
# verification; tzdata so report timestamps render in the operator's timezone.
RUN apk add --no-cache ca-certificates tzdata wget \
    && addgroup -g 10001 -S dnsdaddy \
    && adduser -u 10001 -S -G dnsdaddy dnsdaddy \
    && mkdir -p /var/lib/dnsdaddy \
    && chown -R dnsdaddy:dnsdaddy /var/lib/dnsdaddy

COPY --from=build /out/dnsdaddy /usr/local/bin/dnsdaddy

USER dnsdaddy
WORKDIR /var/lib/dnsdaddy
VOLUME ["/var/lib/dnsdaddy"]

# 53 is DNS, 8080 is the dashboard and API, 853 is DNS-over-TLS.
EXPOSE 53/udp 53/tcp 8080/tcp 853/tcp

# The container runs unprivileged, so it cannot bind 53 directly. Compose
# publishes host 53 to container 5353; see docker-compose.yml.
ENV DNSDADDY_DNS_LISTEN_UDP=:5353 \
    DNSDADDY_DNS_LISTEN_TCP=:5353 \
    DNSDADDY_HTTP_LISTEN=:8080 \
    DNSDADDY_DATA_DIR=/var/lib/dnsdaddy

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/dnsdaddy"]
