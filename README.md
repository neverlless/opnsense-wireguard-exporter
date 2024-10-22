# Prometheus OPNsense Wireguard Exporter

## Introduction

A Prometheus exporter for [WireGuard](https://www.wireguard.com) that operates on [OPNsense](https://opnsense.org/), written in Go. This tool exports data from the OPNsense API in a format that [Prometheus](https://prometheus.io/) can understand. The exporter is efficient, with minimal impact on server resources in terms of memory and CPU usage.

## Features

- **WireGuard Metrics**: Collects metrics such as data transfer, handshake times, and peer statuses from WireGuard interfaces.
- **Interface Traffic Metrics**: Provides metrics on total bytes received and transmitted by network interfaces.
- **Country Code Resolution**: Determines the country code for each peer's endpoint IP using `ip-api.com`, with rate limiting to prevent excessive API requests.
- **Caching**: Implements caching for country codes to minimize redundant API requests.

## Setup

### Docker

1. Ensure Docker is installed on your system.
2. Obtain your [OPNsense](https://opnsense.org/) API endpoint and credentials.
3. Ensure you have WireGuard interfaces running.
4. Download and run the container with:

    ```sh
    docker run -d -p 9486:9486 \
    -e OPNSENSE_API_KEY='YOUR_API_KEY' \
    -e OPNSENSE_API_SECRET='YOUR_API_SECRET' \
    -e OPNSENSE_BASE_URL='YOUR_API_URL' \
    --name opnsense-wireguard-exporter \
    neverlless/opnsense-wireguard-exporter
    ```

5. Verify it's running by visiting [http://localhost:9486/metrics](http://localhost:9486/metrics).

To update the image:

```sh
docker pull neverlless/opnsense-wireguard-exporter
```

Alternatively, use a [tagged image](https://hub.docker.com/r/neverlless/opnsense-wireguard-exporter/tags) such as `:1.0.0`.

For `amd64` or `i686` CPUs, build the Docker image from source with:

```sh
docker build -t neverlless/opnsense-wireguard-exporter https://github.com/neverlless/opnsense-wireguard-exporter.git#main
```

## Usage

### Environment Variables

| Env | Mandatory | Valid Values | Default | Description |
| -- | -- | -- | -- | -- |
| `OPNSENSE_API_KEY` | Yes | `YOUR_API_KEY` |  | API key for OPNsense. |
| `OPNSENSE_API_SECRET` | Yes | `YOUR_API_SECRET` | | API secret for OPNsense. |
| `OPNSENSE_BASE_URL` | Yes | `https://your-opnsense-url` | | Base URL for the OPNsense API. |
| `LISTEN_ADDRESS` | No | `:9486`| `:9486`| Address to listen on for HTTP requests. |
| `METRICS_ENDPOINT_PATH` | No | `/metrics` | `/metrics` | Path for HTTP requests. |

Once started, the exporter listens on the specified port (default 9486) and serves metrics at the `/metrics` endpoint: [http://localhost:9486/metrics](http://localhost:9486/metrics).

### Metrics Exposed

```plaintext
# HELP wireguard_peer_transfer_rx_bytes Received bytes from the peer.
# TYPE wireguard_peer_transfer_rx_bytes gauge
wireguard_peer_transfer_rx_bytes{interface="wg0",peer_name="user1",public_key="..."} 183982

# HELP wireguard_peer_transfer_tx_bytes Sent bytes to the peer.
# TYPE wireguard_peer_transfer_tx_bytes gauge
wireguard_peer_transfer_tx_bytes{interface="wg0",peer_name="user1",public_key="..."} 1163919

# HELP wireguard_peer_latest_handshake Latest handshake time with the peer as UNIX timestamp.
# TYPE wireguard_peer_latest_handshake gauge
wireguard_peer_latest_handshake{interface="wg0",peer_name="user1",public_key="..."} 1708611214

# HELP wireguard_peer_country_code Country code of the WireGuard peer.
# TYPE wireguard_peer_country_code gauge
wireguard_peer_country_code{interface="wg0",peer_name="user1",public_key="...",country_code="US"} 1

# HELP interfaces_received_bytes_total Total bytes received by the interface.
# TYPE interfaces_received_bytes_total gauge
interfaces_received_bytes_total{interface="eth0",device="eth0",name="LAN"} 314980285383

# HELP interfaces_transmitted_bytes_total Total bytes transmitted by the interface.
# TYPE interfaces_transmitted_bytes_total gauge
interfaces_transmitted_bytes_total{interface="eth0",device="eth0",name="LAN"} 684116309877
```

## TODO

- [ ] Add metrics for general traffic information through the firewall.
- [ ] Add metrics for local area network interfaces.
- [ ] Add metrics for firewall declined packets.
- [ ] Provide a Grafana dashboard example.
