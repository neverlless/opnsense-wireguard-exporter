# OPNsense WireGuard Exporter

[![Test](https://github.com/neverlless/opnsense-wireguard-exporter/actions/workflows/test.yml/badge.svg)](https://github.com/neverlless/opnsense-wireguard-exporter/actions/workflows/test.yml)
[![Latest release](https://img.shields.io/github/v/release/neverlless/opnsense-wireguard-exporter)](https://github.com/neverlless/opnsense-wireguard-exporter/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/neverlless/opnsense-wireguard-exporter)](go.mod)
[![GHCR](https://img.shields.io/badge/image-ghcr.io-blue)](https://github.com/neverlless/opnsense-wireguard-exporter/pkgs/container/opnsense-wireguard-exporter)

Prometheus exporter for [WireGuard](https://www.wireguard.com) on [OPNsense](https://opnsense.org/), built on the OPNsense API.

## Features

- Per-peer transfer, handshake, keepalive, allowed IP and endpoint metrics
- WireGuard interface status and traffic counters for network interfaces
- Peer country codes from a GeoLite2 database (optional)
- Scrape health metrics, so failures to reach the OPNsense API are visible
- Stale peer and endpoint series are cleared on each successful update
- IPv6 endpoints and peers with multiple allowed IPs are handled
- Linux images for `amd64` and `arm64`

## Quick start

You need an OPNsense API key and secret, see [OPNsense setup](#opnsense-setup).

```sh
export OPNSENSE_API_KEY='your-api-key'
export OPNSENSE_API_SECRET='your-api-secret'

docker run -d --name opnsense-wireguard-exporter -p 9486:9486 \
  -e OPNSENSE_API_KEY \
  -e OPNSENSE_API_SECRET \
  -e OPNSENSE_BASE_URL='https://opnsense.example.com' \
  ghcr.io/neverlless/opnsense-wireguard-exporter:2

curl http://localhost:9486/metrics
```

### Docker Compose

Secrets come from the environment or a `.env` file next to `compose.yaml`:

```yaml
services:
  opnsense-wireguard-exporter:
    image: ghcr.io/neverlless/opnsense-wireguard-exporter:2
    restart: unless-stopped
    ports:
      - "9486:9486"
    environment:
      OPNSENSE_API_KEY: ${OPNSENSE_API_KEY:?set OPNSENSE_API_KEY}
      OPNSENSE_API_SECRET: ${OPNSENSE_API_SECRET:?set OPNSENSE_API_SECRET}
      OPNSENSE_BASE_URL: https://opnsense.example.com
```

### Prometheus

```yaml
scrape_configs:
  - job_name: opnsense-wireguard
    static_configs:
      - targets:
          - exporter-host:9486
```

### Other install options

Image tags: `2.0.0`, `2.0`, `2` and `latest`, for `linux/amd64` and `linux/arm64`.

Binaries are on [GitHub Releases](https://github.com/neverlless/opnsense-wireguard-exporter/releases).

To build from source you need Go 1.27:

```sh
git clone https://github.com/neverlless/opnsense-wireguard-exporter.git
cd opnsense-wireguard-exporter
go build
```

## Configuration

All configuration is through environment variables. Invalid configuration exits at startup.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `OPNSENSE_API_KEY` | Yes | | OPNsense API key. |
| `OPNSENSE_API_SECRET` | Yes | | OPNsense API secret. |
| `OPNSENSE_BASE_URL` | Yes | | `http` or `https` URL of OPNsense. A trailing slash is fine. |
| `OPNSENSE_TLS_INSECURE` | No | `true` | Skips certificate verification, see [TLS](#tls). |
| `OPNSENSE_CA_FILE` | No | | PEM CA bundle. When set, verification is always on. |
| `GEOLITE_DB_PATH` | No | `/opt/GeoLite2-Country.mmdb` | GeoLite2 Country database. If missing, peers report `country_code="unknown"`. |
| `METRICS_UPDATE_INTERVAL_SECONDS` | No | `30` | How often metrics are refreshed from OPNsense. Must be greater than 0. |
| `LISTEN_ADDRESS` | No | `:9486` | Address the HTTP server listens on. |
| `METRICS_ENDPOINT_PATH` | No | `/metrics` | Path that serves metrics. |

### OPNsense setup

OPNsense API keys belong to a user. Create a dedicated user with access to only the WireGuard and diagnostics traffic pages, then create an API key for it.

The exporter calls two API endpoints:

- `/api/wireguard/service/show`
- `/api/diagnostics/traffic/interface`

### TLS

`OPNSENSE_TLS_INSECURE` defaults to `true` because OPNsense usually has a self-signed certificate. In this mode the exporter does not verify the certificate, so anyone able to intercept the connection can read the API credentials.

For a self-signed certificate, the recommended setup is to give the exporter the CA with `OPNSENSE_CA_FILE`. Verification is then always on, whatever `OPNSENSE_TLS_INSECURE` says:

```sh
docker run -d --name opnsense-wireguard-exporter -p 9486:9486 \
  -e OPNSENSE_API_KEY \
  -e OPNSENSE_API_SECRET \
  -e OPNSENSE_BASE_URL='https://opnsense.example.com' \
  -e OPNSENSE_CA_FILE=/etc/opnsense/ca.pem \
  -v "$PWD/opnsense-ca.pem:/etc/opnsense/ca.pem:ro" \
  ghcr.io/neverlless/opnsense-wireguard-exporter:2
```

The host name in `OPNSENSE_BASE_URL` must match the certificate. If OPNsense has a certificate from a publicly trusted CA, set `OPNSENSE_TLS_INSECURE=false` instead.

## Metrics

Peer labels below means `interface`, `peer_name` and `public_key`.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `wireguard_peer_transfer_rx_bytes_total` | counter | peer labels | Bytes received from the peer. |
| `wireguard_peer_transfer_tx_bytes_total` | counter | peer labels | Bytes sent to the peer. |
| `wireguard_peer_latest_handshake` | gauge | peer labels | Latest handshake as a Unix timestamp. |
| `wireguard_peer_last_handshake_age_seconds` | gauge | peer labels | Seconds since the latest handshake. |
| `wireguard_peer_persistent_keepalive_seconds` | gauge | peer labels | Persistent keepalive interval, 0 if disabled. |
| `wireguard_peer_allowed_ips` | gauge | peer labels, `allowed_ip` | One series per allowed IP, CIDR kept. Value is 1. |
| `wireguard_peer_endpoint` | gauge | peer labels, `endpoint_ip` | Peer endpoint IP. Value is 1. |
| `wireguard_peer_country_code` | gauge | peer labels, `country_code` | Country of the peer endpoint. Value is 1. |
| `wireguard_interface_status` | gauge | `interface`, `name` | WireGuard interface status: 1 up, 0 down. |
| `wireguard_up` | gauge | | 1 if the last update from the OPNsense API fully succeeded, otherwise 0. |
| `wireguard_scrape_errors_total` | counter | | Failed OPNsense API update cycles. |
| `wireguard_last_scrape_timestamp_seconds` | gauge | | Unix timestamp of the last fully successful update. |
| `interfaces_received_bytes_total` | counter | `interface`, `device`, `name` | Bytes received by the network interface. |
| `interfaces_transmitted_bytes_total` | counter | `interface`, `device`, `name` | Bytes transmitted by the network interface. |

## Operations

### Endpoints

- `/metrics`, or the path set in `METRICS_ENDPOINT_PATH`: Prometheus metrics.
- `/healthz`: liveness only. It does not check OPNsense, use `wireguard_up` for that.

### Example alerts

The stale handshake rule only covers peers with persistent keepalive, because idle peers without it do not handshake on a schedule. Adjust the thresholds to your setup.

```yaml
groups:
  - name: opnsense-wireguard
    rules:
      - alert: WireGuardExporterAPIFailure
        expr: wireguard_up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: Exporter cannot read from the OPNsense API
      - alert: WireGuardPeerStaleHandshake
        expr: wireguard_peer_last_handshake_age_seconds > 600 and wireguard_peer_persistent_keepalive_seconds > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'Peer {{ $labels.peer_name }} on {{ $labels.interface }} has a stale handshake'
      - alert: WireGuardInterfaceDown
        expr: wireguard_interface_status == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: 'WireGuard interface {{ $labels.interface }} is down'
```

### Grafana

Import the dashboard from [`grafana/WireGuard Dashboard-1729676220092.json`](grafana/WireGuard%20Dashboard-1729676220092.json).

### GeoIP

The image ships a pinned GeoLite2 Country database, so `country_code` works out of the box. To use your own copy, mount it and point `GEOLITE_DB_PATH` at it.

GeoLite2 data is created by [MaxMind](https://www.maxmind.com) and is subject to the [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula).

## Upgrading from v1

- **Metric rename:** `wireguard_peer_transfer_rx_bytes` and `wireguard_peer_transfer_tx_bytes` are now `wireguard_peer_transfer_rx_bytes_total` and `wireguard_peer_transfer_tx_bytes_total`, and they are counters. Update dashboards and alerts, for example to `rate(wireguard_peer_transfer_rx_bytes_total[5m])`.
- **`allowed_ip` keeps the CIDR:** for example `10.0.0.2/32`. Update queries that match the bare IP.
- **Image moved to GHCR:** use `ghcr.io/neverlless/opnsense-wireguard-exporter`. Docker Hub images under `neverlless/opnsense-wireguard-exporter` no longer receive updates.
- **Config is validated at startup:** invalid values now exit instead of failing later.
- **Logs are plain `slog` text without colours:** update anything that parses them.

## Troubleshooting

**HTML instead of JSON error.** OPNsense returned a web page instead of an API response. Check that `OPNSENSE_BASE_URL` uses HTTPS and that the API key and secret are correct.

**`wireguard_up 0`.** The exporter could not complete an update from the OPNsense API. The exporter logs give the reason. Common causes are an unreachable URL, wrong credentials, a user missing access to one of the [two API endpoints](#opnsense-setup), or a certificate that fails verification.

**`country_code="unknown"`.** The GeoLite2 database could not be opened, or the peer has no endpoint yet. Check `GEOLITE_DB_PATH` and the startup logs.

## Contributing

Issues and pull requests are welcome. Run the tests before opening a pull request:

```sh
go test -race ./...
```

## Roadmap

- Metrics for general traffic through the firewall
- Metrics for local area network interfaces
- Metrics for packets blocked by the firewall

## License

[MIT](LICENSE). The GeoLite2 database shipped in the image is covered by MaxMind's own terms.
