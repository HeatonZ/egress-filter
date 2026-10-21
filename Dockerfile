# Build stage. CGO is off because the binary uses only the standard library's
# resolver, which keeps the image portable and the build reproducible.
FROM golang:1.23-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/egress-filter ./cmd/egress-filter

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 app

COPY --from=build /out/egress-filter /usr/local/bin/egress-filter

USER app
# 8080 reverse, 1080 forward, 9090 status, 1081 TLS-terminating forward.
EXPOSE 8080 1080 9090 1081
# The signing CA lives here. It must be a volume: regenerating it would
# invalidate every client that trusts the old one.
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD wget -qO- http://127.0.0.1:9090/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/egress-filter"]
