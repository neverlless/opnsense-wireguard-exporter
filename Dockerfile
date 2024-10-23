FROM golang:1.23.1 AS builder

WORKDIR /src

COPY . .

RUN go get -v . \
    && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o opnsense-wireguard-exporter

FROM alpine:3.19.1

WORKDIR /opt

COPY --from=builder /src/opnsense-wireguard-exporter opnsense-wireguard-exporter

RUN wget -O GeoLite2-Country.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb \
    && chmod 755 /opt/opnsense-wireguard-exporter

CMD [ "/opt/opnsense-wireguard-exporter" ]
