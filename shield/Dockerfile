# Morrow Shield: one static binary on distroless, as a non-root user, read-only filesystem friendly.
#   docker build -t morrow-shield shield/
# The only writable path it needs is /data (the ACME certificate cache): mount a volume there and
# run with --read-only.
FROM golang:1.26-alpine AS build
ARG VERSION=dev
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/shield . \
 && mkdir -p /out/data/acme

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/shield /usr/local/bin/shield
# Owned by the nonroot user (65532), so a fresh named volume mounted at /data is writable by it.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
# Unprivileged ports inside the container; publish them as 443 and 80 (-p 443:8443 -p 80:8080).
ENV SHIELD_LISTEN=:8443 \
    SHIELD_HTTP_LISTEN=:8080 \
    SHIELD_HEALTH_LISTEN=127.0.0.1:9180 \
    SHIELD_ACME_DIR=/data/acme
EXPOSE 8443 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/usr/local/bin/shield", "health"]
ENTRYPOINT ["/usr/local/bin/shield"]
