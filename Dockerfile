FROM golang:1.25.5 AS builder

WORKDIR /src

COPY . .

ARG VERSION=dev
RUN go get -v . \
    && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
       -ldflags "-s -w -X main.version=${VERSION}" \
       -o opnsense-wireguard-exporter

FROM alpine:3.19.1

RUN apk add --no-cache ca-certificates wget \
    && addgroup -S app && adduser -S -G app app

WORKDIR /opt

COPY --from=builder /src/opnsense-wireguard-exporter opnsense-wireguard-exporter

RUN wget -O GeoLite2-Country.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb \
    && chmod 755 /opt/opnsense-wireguard-exporter \
    && chown -R app:app /opt

USER app

EXPOSE 9486

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:9486/healthz || exit 1

CMD [ "/opt/opnsense-wireguard-exporter" ]
