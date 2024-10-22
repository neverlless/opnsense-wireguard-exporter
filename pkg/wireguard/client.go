package wireguard

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	timeLayout               = "2006-01-02 15:04:05-07:00"
	defaultHTTPClientTimeout = 10 * time.Second
)

type Client struct {
	BaseURL    string
	APIKey     string
	APISecret  string
	HTTPClient *http.Client
}

var (
	wgPeerTransferRxMetric          = newGaugeVec("wireguard_peer_transfer_rx_bytes", "Received bytes from the peer.", "interface", "peer_name", "public_key")
	wgPeerTransferTxMetric          = newGaugeVec("wireguard_peer_transfer_tx_bytes", "Sent bytes to the peer.", "interface", "peer_name", "public_key")
	wgPeerLatestHandshakeMetric     = newGaugeVec("wireguard_peer_latest_handshake", "Latest handshake time with the peer as UNIX timestamp.", "interface", "peer_name", "public_key")
	wgPeerAllowedIPsMetric          = newGaugeVec("wireguard_peer_allowed_ips", "Allowed IPs for the WireGuard peer.", "interface", "peer_name", "public_key", "allowed_ip")
	wgPeerEndpointMetric            = newGaugeVec("wireguard_peer_endpoint", "Endpoint of the WireGuard peer.", "interface", "peer_name", "public_key", "endpoint_ip")
	interfaceReceivedBytesMetric    = newGaugeVec("interfaces_received_bytes_total", "Total bytes received by the interface.", "interface", "device", "name")
	interfaceTransmittedBytesMetric = newGaugeVec("interfaces_transmitted_bytes_total", "Total bytes transmitted by the interface.", "interface", "device", "name")
)

func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

func init() {
	prometheus.MustRegister(
		wgPeerTransferRxMetric,
		wgPeerTransferTxMetric,
		wgPeerLatestHandshakeMetric,
		wgPeerAllowedIPsMetric,
		wgPeerEndpointMetric,
		interfaceReceivedBytesMetric,
		interfaceTransmittedBytesMetric,
	)

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	log.SetLevel(log.InfoLevel)
}

func NewClient(apiKey, apiSecret, baseURL string) (*Client, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{
		Timeout: defaultHTTPClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	log.WithFields(log.Fields{"baseURL": baseURL}).Info("Connected to OPNsense")

	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		APISecret:  apiSecret,
		HTTPClient: client,
	}, nil
}

func (c *Client) UpdateMetrics() error {
	log.Println("Updating metrics...")

	// Update WireGuard metrics
	body, err := c.fetch("/api/wireguard/service/show")
	if err != nil {
		log.Errorf("Error fetching WireGuard configuration: %v", err)
		return err
	}

	var wgStatus WireGuardStatus
	err = json.Unmarshal(body, &wgStatus)
	if err != nil {
		log.Errorf("Failed to parse WireGuard config: %v", err)
		return fmt.Errorf("failed to parse WireGuard config: %v", err)
	}

	updateWireGuardMetrics(wgStatus.Rows)

	// Update interface metrics
	body, err = c.fetch("/api/diagnostics/traffic/interface")
	if err != nil {
		log.Errorf("Error fetching interface traffic data: %v", err)
		return err
	}

	var interfaceTraffic InterfaceTrafficStatus
	err = json.Unmarshal(body, &interfaceTraffic)
	if err != nil {
		log.Errorf("Failed to parse interface traffic data: %v", err)
		return fmt.Errorf("failed to parse interface traffic data: %v", err)
	}

	updateInterfaceMetrics(interfaceTraffic.Interfaces)

	log.Println("Metrics updated successfully.")
	return nil
}

func (c *Client) fetch(endpoint string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+endpoint, nil)
	if err != nil {
		log.WithError(err).Error("Failed to create request")
		return nil, err
	}

	req.SetBasicAuth(c.APIKey, c.APISecret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.WithError(err).Error("Failed to perform request")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return body, nil
}

func updateWireGuardMetrics(rows []PeerStatus) {
	for _, row := range rows {
		if row.Type == "peer" {
			wgPeerTransferRxMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(row.TransferRx))
			wgPeerTransferTxMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(row.TransferTx))
			wgPeerLatestHandshakeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(row.LatestHandshake))

			// Extract IP address without prefix for Allowed IPs
			allowedIP := strings.Split(row.AllowedIPs, "/")[0]
			wgPeerAllowedIPsMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, allowedIP).Set(1)

			// Extract IP address without port for Endpoint
			endpointIP := strings.Split(row.Endpoint, ":")[0]
			wgPeerEndpointMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, endpointIP).Set(1)
		}
	}
}

func updateInterfaceMetrics(interfaces map[string]InterfaceData) {
	for name, data := range interfaces {
		// Convert received bytes from string to int64
		bytesReceived, err := strconv.ParseInt(data.BytesReceived, 10, 64)
		if err != nil {
			log.WithError(err).Errorf("Failed to parse bytes received for interface %s", name)
			continue
		}
		interfaceReceivedBytesMetric.WithLabelValues(name, data.Device, data.Name).Set(float64(bytesReceived))

		// Convert transmitted bytes from string to int64
		bytesTransmitted, err := strconv.ParseInt(data.BytesTransmitted, 10, 64)
		if err != nil {
			log.WithError(err).Errorf("Failed to parse bytes transmitted for interface %s", name)
			continue
		}
		interfaceTransmittedBytesMetric.WithLabelValues(name, data.Device, data.Name).Set(float64(bytesTransmitted))
	}
}
