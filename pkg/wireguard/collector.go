package wireguard

import (
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	wgPeerTransferRxDesc      = newPeerDesc("wireguard_peer_transfer_rx_bytes", "Received bytes from the peer.")
	wgPeerTransferTxDesc      = newPeerDesc("wireguard_peer_transfer_tx_bytes", "Sent bytes to the peer.")
	wgPeerLatestHandshakeDesc = newPeerDesc("wireguard_peer_latest_handshake", "Latest handshake time with the peer as UNIX timestamp.")
	wgPeerAllowedIPsDesc      = newPeerDesc("wireguard_peer_allowed_ips", "Allowed IPs for the WireGuard peer.", "allowed_ip")
	wgPeerEndpointDesc        = newPeerDesc("wireguard_peer_endpoint", "Endpoint of the WireGuard peer.", "endpoint_ip")
	wgPeerCountryCodeDesc     = newPeerDesc("wireguard_peer_country_code", "Country code of the WireGuard peer.", "country_code")
	wgPeerHandshakeAgeDesc    = newPeerDesc("wireguard_peer_last_handshake_age_seconds", "Seconds since the peer's latest handshake.")
	wgPeerKeepaliveDesc       = newPeerDesc("wireguard_peer_persistent_keepalive_seconds", "Persistent keepalive interval for the peer in seconds (0 if disabled).")
	wgInterfaceStatusDesc     = prometheus.NewDesc("wireguard_interface_status", "WireGuard interface status (1 = up, 0 = down).", []string{"interface", "name"}, nil)
	ifReceivedBytesDesc       = prometheus.NewDesc("interfaces_received_bytes_total", "Total bytes received by the interface.", []string{"interface", "device", "name"}, nil)
	ifTransmittedBytesDesc    = prometheus.NewDesc("interfaces_transmitted_bytes_total", "Total bytes transmitted by the interface.", []string{"interface", "device", "name"}, nil)
)

func newPeerDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, append([]string{"interface", "peer_name", "public_key"}, extraLabels...), nil)
}

// snapshotCollector exposes the state of the last successful update. Replacing
// the whole snapshot at once means a scrape never sees a partial update, and
// the values originate from OPNsense as absolute numbers, so they are emitted
// as ConstMetrics instead of settable gauges.
type snapshotCollector struct {
	mu       sync.RWMutex
	snapshot []prometheus.Metric
}

// Update replaces the snapshot used for the next scrape.
func (c *snapshotCollector) Update(metrics []prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = metrics
}

func (c *snapshotCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		wgPeerTransferRxDesc,
		wgPeerTransferTxDesc,
		wgPeerLatestHandshakeDesc,
		wgPeerAllowedIPsDesc,
		wgPeerEndpointDesc,
		wgPeerCountryCodeDesc,
		wgPeerHandshakeAgeDesc,
		wgPeerKeepaliveDesc,
		wgInterfaceStatusDesc,
		ifReceivedBytesDesc,
		ifTransmittedBytesDesc,
	} {
		ch <- desc
	}
}

func (c *snapshotCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()

	for _, metric := range snapshot {
		ch <- metric
	}
}

// buildSnapshot turns the API responses into metrics. When a series repeats, the
// first occurrence wins: a duplicate would make the whole Gather fail.
func (c *Client) buildSnapshot(rows []PeerStatus, interfaces map[string]InterfaceData) []prometheus.Metric {
	var metrics []prometheus.Metric
	seen := make(map[string]bool)
	add := func(desc *prometheus.Desc, valueType prometheus.ValueType, value float64, labels ...string) {
		key := desc.String() + "\x00" + strings.Join(labels, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		metrics = append(metrics, prometheus.MustNewConstMetric(desc, valueType, value, labels...))
	}

	for _, row := range rows {
		switch row.Type {
		case "interface":
			status := 0.0
			if row.Status == "up" {
				status = 1
			}
			add(wgInterfaceStatusDesc, prometheus.GaugeValue, status, row.Ifname, row.Name)
		case "peer":
			peer := []string{row.Ifname, row.Name, row.PublicKey}
			add(wgPeerTransferRxDesc, prometheus.GaugeValue, float64(row.TransferRx), peer...)
			add(wgPeerTransferTxDesc, prometheus.GaugeValue, float64(row.TransferTx), peer...)
			add(wgPeerLatestHandshakeDesc, prometheus.GaugeValue, float64(row.LatestHandshake), peer...)
			add(wgPeerKeepaliveDesc, prometheus.GaugeValue, parseKeepalive(row.PersistentKeepalive), peer...)

			if row.LatestHandshakeAge != nil {
				add(wgPeerHandshakeAgeDesc, prometheus.GaugeValue, float64(*row.LatestHandshakeAge), peer...)
			}

			// One series per allowed IP so peers with multiple allowed-ips are fully represented.
			for _, allowedIP := range splitAllowedIPs(row.AllowedIPs) {
				add(wgPeerAllowedIPsDesc, prometheus.GaugeValue, 1, append(peer, allowedIP)...)
			}

			countryCode := "unknown"
			if endpointIP := endpointHost(row.Endpoint); endpointIP != "" {
				add(wgPeerEndpointDesc, prometheus.GaugeValue, 1, append(peer, endpointIP)...)

				var err error
				if countryCode, err = c.getCountryCode(endpointIP); err != nil {
					slog.Warn("Failed to get country code", "ip", endpointIP, "error", err)
				}
			}
			add(wgPeerCountryCodeDesc, prometheus.GaugeValue, 1, append(peer, countryCode)...)
		}
	}

	for name, data := range interfaces {
		for desc, raw := range map[*prometheus.Desc]string{
			ifReceivedBytesDesc:    data.BytesReceived,
			ifTransmittedBytesDesc: data.BytesTransmitted,
		} {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				slog.Error("Failed to parse interface byte counter", "interface", name, "error", err)
				continue
			}
			add(desc, prometheus.CounterValue, float64(value), name, data.Device, data.Name)
		}
	}

	return metrics
}
