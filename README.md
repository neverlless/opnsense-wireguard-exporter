# Prometheus OPNsense Wireguard Exporter

## Intro

A Prometheus exporter for [WireGuard](https://www.wireguard.com) worked on [OPNsense](https://opnsense.org/), written in Go. This tool exports the data from OPNsense api results in a format that [Prometheus](https://prometheus.io/) can understand. The exporter is very light on your server resources, both in terms of memory and CPU usage.

## Setup

### Docker

1. You need Docker installed
2. You need [OPNsense](https://opnsense.org/) api endpoint and credentials.
3. You need some Wireguard interfaces running
4. Download and run the container with:

    ```sh
    docker run -d -p 9486:9486 \
    -e OPNSENSE_API_KEY='YOUR_API_KEY' \
    -e OPNSENSE_API_SECRET='YOUR_API_SECRET' \
    -e OPNSENSE_BASE_URL='YOUR_API_URL' \
    --name opnsense-wireguard-exporter \
    neverlless/opnsense-wireguard-exporter
    ```

5. Check it's up by visiting [http://localhost:9486/metrics](http://localhost:9486/metrics)

You can then update the image with

```sh
docker pull neverlless/opnsense-wireguard-exporter
```

Or use a [tagged image](https://hub.docker.com/r/neverlless/opnsense-wireguard-exporter/tags) such as `:1.0.0`.

If your host has an `amd64` or `686` CPU, you can also build the Docker image from source (you need `git`) with:

```sh
docker build -t neverlless/opnsense-wireguard-exporter https://github.com/neverlless/opnsense-wireguard-exporter.git#main
```

## Usage

### Envs available

| Env | Mandatory | Valid values | Default | Description |
| -- | -- | -- | -- | -- |
| `OPNSENSE_API_KEY` | Yes | `ezlPhf34oivo4vpr5mumOsdf1ipHrMfN/e4eoXMdaoeofVrfD9kUepl` |  | The API key to use for the OPNsense API. |
| `OPNSENSE_API_SECRET` | Yes | `f3rf34mfoi3rmf34fimvo43vFGIJe3z9AOOP1UCZSd3wUfiy6bHOHXKv141Kz` | | The API secret to use for the OPNsense API. |
| `OPNSENSE_BASE_URL` | Yes | `https://127.0.0.1`| | The base URL to use for the OPNsense API. |
| `LISTEN_ADDRESS` | No | `:9486`| `:9486`| The address to listen on for HTTP requests. |
| `METRICS_ENDPOINT_PATH` | No | `/metrics` | `/metrics` | The path to listen on for HTTP requests. |

Once started, the tool will listen on the specified port (or the default one, 9486, if not specified) and return a Prometheus valid response at the url `/metrics`. So to check if the tool is working properly simply browse the `http://localhost:9586/metrics` (or whichever port you choose).

### Metrics exposed

```ebnf
# HELP opnsense_firmware_connection_status Status of the connection to the firmware repository
# TYPE opnsense_firmware_connection_status gauge
opnsense_firmware_connection_status{status="ok"} 1
# HELP opnsense_firmware_needs_reboot Indicates if a reboot is required after firmware updates
# TYPE opnsense_firmware_needs_reboot gauge
opnsense_firmware_needs_reboot 0
# HELP opnsense_firmware_repository_status Status of the firmware repository
# TYPE opnsense_firmware_repository_status gauge
opnsense_firmware_repository_status{status="ok"} 1
# HELP opnsense_product_version_info The current version of the OPNsense product
# TYPE opnsense_product_version_info gauge
opnsense_product_version_info{version="23.7.3"} 1
# HELP wireguard_interface_info Information about the WireGuard interface.
# TYPE wireguard_interface_info gauge
wireguard_interface_info{interface="wg0",listening_port="",public_key=""} 1
# HELP wireguard_peer_last_handshake_seconds Last handshake time with the peer as UNIX timestamp.
# TYPE wireguard_peer_last_handshake_seconds gauge
wireguard_peer_last_handshake_seconds{interface="wg0",peer_name="user1",public_key="iojfo4i344njnvernvlsvr4TQ="} 1.708611214e+09
wireguard_peer_last_handshake_seconds{interface="wg0",peer_name="usertest",public_key="e/foweifjo34ivndlksvn4c="} 1.708595705e+09
# HELP wireguard_peer_status Status of the WireGuard peer (enabled/disabled).
# TYPE wireguard_peer_status gauge
wireguard_peer_status{interface="wg0",peer_name="user1",public_key="iojfo4i344njnvernvlsvr4TQ="} 1
wireguard_peer_status{interface="wg0",peer_name="usertest",public_key="e/foweifjo34ivndlksvn4c="} 1
# HELP wireguard_peer_transfer_bytes Number of bytes transferred to and from the peer.
# TYPE wireguard_peer_transfer_bytes gauge
wireguard_peer_transfer_bytes{direction="received",interface="wg0",peer_public_key="iojfo4i344njnvernvlsvr4TQ="} 183982
wireguard_peer_transfer_bytes{direction="received",interface="wg0",peer_public_key="e/foweifjo34ivndlksvn4c="} 0
wireguard_peer_transfer_bytes{direction="sent",interface="wg0",peer_public_key="iojfo4i344njnvernvlsvr4TQ="} 1.163919e+06
wireguard_peer_transfer_bytes{direction="sent",interface="wg0",peer_public_key="e/foweifjo34ivndlksvn4c="} 0
# HELP wireguard_total_peers Total number of WireGuard peers.
# TYPE wireguard_total_peers gauge
wireguard_total_peers 89
```

## TODO

- [ ] Add metrics General information on traffic passing through the firewall
- [ ] Add metrics LA network interfaces
- [ ] Add metrics Firewall declained packets
- [ ] Grafana dashboard example
