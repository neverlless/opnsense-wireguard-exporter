# Runs natively; Go cross-compiles, so arm64 builds do not go through emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

WORKDIR /src

# GeoLite2-Country 2026.10.28. Pinned by commit because upstream keeps only its
# two newest releases, so dated release URLs 404 within about a week.
# To refresh, set GEOLITE_COMMIT and GEOLITE_SHA256 from:
#   gh api repos/P3TERX/GeoLite.mmdb/commits/download --jq .sha
#   curl -fsSL https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/<sha>/GeoLite2-Country.mmdb | sha256sum
ARG GEOLITE_COMMIT=96c86b69edea38760cc754247627367ea2e4742c
ARG GEOLITE_SHA256=54e327d9fe9214e568c5b8f8ce97a7f7e7087b7de10b0560640417695d153797
RUN wget -q -O /GeoLite2-Country.mmdb \
       "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/${GEOLITE_COMMIT}/GeoLite2-Country.mmdb" \
    && echo "${GEOLITE_SHA256}  /GeoLite2-Country.mmdb" | sha256sum -c -

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
       -ldflags "-s -w -X main.version=${VERSION}" \
       -o opnsense-wireguard-exporter

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

LABEL org.opencontainers.image.source="https://github.com/neverlless/opnsense-wireguard-exporter"

RUN apk add --no-cache ca-certificates \
    && addgroup -S app && adduser -S -G app app

WORKDIR /opt

COPY --from=builder --chown=app:app /src/opnsense-wireguard-exporter /GeoLite2-Country.mmdb ./

USER app

EXPOSE 9486

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD p="${LISTEN_ADDRESS:-:9486}"; wget -q -O /dev/null "http://127.0.0.1:${p##*:}/healthz" || exit 1

CMD [ "/opt/opnsense-wireguard-exporter" ]
