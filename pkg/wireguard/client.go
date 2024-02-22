package wireguard

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	timeLayout               = "2006-01-02 15:04:05-07:00" // Time layout for parsing timestamps
	defaultHTTPClientTimeout = 10 * time.Second            // HTTP client timeout duration
)

// Client represents a client for interacting with the OPNsense API.
type Client struct {
	BaseURL    string
	APIKey     string
	APISecret  string
	HTTPClient *http.Client
}

// Define Prometheus metrics for monitoring various statuses and configurations.
var (
	// Firmware-related metrics.
	needsRebootMetric      = newGauge("opnsense_firmware_needs_reboot", "Indicates if a reboot is required after firmware updates")
	connectionStatusMetric = newGaugeVec("opnsense_firmware_connection_status", "Status of the connection to the firmware repository", "status")
	repositoryStatusMetric = newGaugeVec("opnsense_firmware_repository_status", "Status of the firmware repository", "status")
	productVersionMetric   = newGaugeVec("opnsense_product_version_info", "The current version of the OPNsense product", "version")

	// WireGuard-related metrics.
	wgPeerLastHandshakeMetric = newGaugeVec("wireguard_peer_last_handshake_seconds", "Last handshake time with the peer as UNIX timestamp.", "interface", "peer_name", "public_key")
	wgPeerStatusMetric        = newGaugeVec("wireguard_peer_status", "Status of the WireGuard peer (enabled/disabled).", "interface", "peer_name", "public_key")
	wgTotalPeersMetric        = newGauge("wireguard_total_peers", "Total number of WireGuard peers.")
	wgInterfaceInfoMetric     = newGaugeVec("wireguard_interface_info", "Information about the WireGuard interface.", "interface", "public_key", "listening_port")
	wgPeerTransferMetric      = newGaugeVec("wireguard_peer_transfer_bytes", "Number of bytes transferred to and from the peer.", "interface", "peer_public_key", "direction") // "direction" can be "received" or "sent"
)

// newGauge creates a new prometheus.Gauge and returns it.
func newGauge(name, help string) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
}

// newGaugeVec creates a new prometheus.GaugeVec and returns it.
func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

func init() {
	// Register new metrics with Prometheus.
	prometheus.MustRegister(
		needsRebootMetric,
		connectionStatusMetric,
		repositoryStatusMetric,
		productVersionMetric,
		wgPeerLastHandshakeMetric,
		wgPeerStatusMetric,
		wgTotalPeersMetric,
		wgInterfaceInfoMetric,
		wgPeerTransferMetric,
	)

	// Configure logging with logrus.
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	log.SetLevel(log.InfoLevel)
}

// FetchWireGuardConfig fetches the WireGuard configuration from the endpoint and updates relevant metrics.
func (c *Client) FetchWireGuardConfig() error {
	log.Println("Fetching WireGuard configuration...")

	body, err := c.fetch("/api/wireguard/service/showconf")
	if err != nil {
		log.Errorf("Error fetching WireGuard configuration: %v", err)
		return err
	}

	interfaces, peers, err := parseWireGuardConfig(body)
	if err != nil {
		log.Errorf("Failed to parse WireGuard config: %v", err)
		return fmt.Errorf("failed to parse WireGuard config: %v", err)
	}

	log.Println("Updating WireGuard metrics...")
	updateWireGuardMetrics(interfaces, peers)
	log.Println("WireGuard metrics updated successfully.")

	return nil
}

// UpdateMetrics updates firmware and WireGuard-related metrics by interfacing with the OPNsense API.
func (c *Client) UpdateMetrics() error {
	firmwareStatus, err := c.FetchFirmwareStatus()
	if err != nil {
		return err
	}

	updateFirmwareMetrics(firmwareStatus)

	wgStatus, err := c.FetchWireGuardStatus()
	if err != nil {
		return err
	}

	totalPeers := updateWireGuardStatusMetrics(wgStatus)

	wgTotalPeersMetric.Set(float64(totalPeers))

	if err = c.FetchWireGuardConfig(); err != nil {
		return err
	}
	return nil
}

// FetchWireGuardStatus fetches the WireGuard status from the OPNsense API and returns the structured representation.
func (c *Client) FetchWireGuardStatus() (*WireGuardStatus, error) {
	body, err := c.fetch("/api/wireguard/general/getStatus")
	if err != nil {
		return nil, err
	}

	var status WireGuardStatus
	err = json.Unmarshal(body, &status)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal WireGuard status: %v", err)
	}

	return &status, nil
}

// NewClient creates a new Client instance for interfacing with the OPNsense API.
func NewClient(apiKey, apiSecret, baseURL string) (*Client, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true} // Skip certificate validation

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

// fetch performs an API request and returns the result body.
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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return body, nil
}

// FetchFirmwareStatus fetches firmware status from the OPNsense API and returns the structured representation.
func (c *Client) FetchFirmwareStatus() (*FirmwareStatus, error) {
	body, err := c.fetch("/api/core/firmware/status")
	if err != nil {
		return nil, err
	}

	var status FirmwareStatus
	err = json.Unmarshal(body, &status)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal firmware status: %v", err)
	}

	return &status, nil
}

// updateFirmwareMetrics updates Prometheus metrics based on the provided firmware status information.
func updateFirmwareMetrics(status *FirmwareStatus) {
	needsReboot, _ := strconv.ParseFloat(status.NeedsReboot, 64)
	needsRebootMetric.Set(needsReboot)

	connectionStatusMetric.WithLabelValues(status.Connection).Set(1)
	repositoryStatusMetric.WithLabelValues(status.Repository).Set(1)
	productVersionMetric.WithLabelValues(status.ProductVersion).Set(1)
}

// updateWireGuardStatusMetrics updates Prometheus metrics based on the provided WireGuard status information and returns the total number of peers.
func updateWireGuardStatusMetrics(wgStatus *WireGuardStatus) (totalPeers int) {
	for _, wg := range wgStatus.Items {
		for _, peer := range wg.Peers {
			lastHandshakeValue := float64(0)
			if peer.LastHandshake != "0000-00-00 00:00:00+00:00" {
				lastHandshakeTime, err := time.Parse(timeLayout, peer.LastHandshake)
				if err != nil {
					log.WithError(err).Error("Failed to parse last handshake time")
					continue
				}
				lastHandshakeValue = float64(lastHandshakeTime.Unix())
			}

			wgPeerLastHandshakeMetric.WithLabelValues(wg.Interface, peer.Name, peer.PublicKey).Set(lastHandshakeValue)
			wgPeerStatusMetric.WithLabelValues(wg.Interface, peer.Name, peer.PublicKey).Set(float64(peer.Enabled))
			totalPeers++
		}
	}
	return totalPeers
}

// updateWireGuardMetrics updates Prometheus metrics based on the provided interfaces and peers from WireGuard configuration.
func updateWireGuardMetrics(interfaces []WireGuardInterface, peers []WireGuardPeer) {
	for _, intf := range interfaces {
		wgInterfaceInfoMetric.WithLabelValues(intf.Name, intf.PublicKey, intf.ListeningPort).Set(1)
	}

	for _, peer := range peers {
		wgPeerTransferMetric.WithLabelValues(peer.Interface, peer.PublicKey, "received").Set(float64(peer.TransferReceived))
		wgPeerTransferMetric.WithLabelValues(peer.Interface, peer.PublicKey, "sent").Set(float64(peer.TransferSent))
	}
}

// parseWireGuardConfig parses the WireGuard configuration and returns structured interface and peer information.
func parseWireGuardConfig(config []byte) ([]WireGuardInterface, []WireGuardPeer, error) {
	var wgConf struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(config, &wgConf); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	lines := strings.Split(wgConf.Response, "\n")

	var (
		interfaces       []WireGuardInterface
		peers            []WireGuardPeer
		currentInterface *WireGuardInterface
	)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "interface:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				currentInterface = &WireGuardInterface{Name: fields[1]}
				interfaces = append(interfaces, *currentInterface)
			}
		case strings.HasPrefix(line, "public key:"):
			fields := strings.Fields(line)
			if currentInterface != nil && len(fields) >= 3 {
				currentInterface.PublicKey = fields[2]
			}
		case strings.HasPrefix(line, "listening port:"):
			fields := strings.Fields(line)
			if currentInterface != nil && len(fields) >= 3 {
				currentInterface.ListeningPort = fields[2]
			}
		case strings.HasPrefix(line, "peer:"):
			fields := strings.Fields(line)
			if currentInterface != nil && len(fields) >= 2 {
				peers = append(peers, WireGuardPeer{
					Interface: currentInterface.Name,
					PublicKey: fields[1],
				})
			}
		case strings.HasPrefix(line, "transfer:"):
			fields := strings.Fields(line)
			if len(peers) > 0 && len(fields) >= 5 {
				lastPeer := &peers[len(peers)-1]
				receivedBytes, sentBytes, err := parseTransferData(fields[1], fields[2], fields[4], fields[5])
				if err != nil {
					return nil, nil, err
				}
				lastPeer.TransferReceived = receivedBytes
				lastPeer.TransferSent = sentBytes
			}
		}
	}

	return interfaces, peers, nil
}

// parseTransferData takes separate strings representing received and sent data (e.g., "19.34 MiB") and returns the values in bytes.
func parseTransferData(received, receivedUnit, sent, sentUnit string) (uint64, uint64, error) {
	receivedBytes, err := parseTransfer(received + " " + receivedUnit)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse received data: %v", err)
	}

	sentBytes, err := parseTransfer(sent + " " + sentUnit)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse sent data: %v", err)
	}

	return receivedBytes, sentBytes, nil
}

// parseTransfer takes a string representing data transfer (e.g., "19.34 MiB") and returns the value in bytes.
func parseTransfer(transfer string) (uint64, error) {
	parts := strings.Fields(transfer)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid transfer data format")
	}

	value, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, err
	}

	switch parts[1] {
	case "KiB":
		return uint64(value * 1024), nil
	case "MiB":
		return uint64(value * 1024 * 1024), nil
	case "GiB":
		return uint64(value * 1024 * 1024 * 1024), nil
	case "TiB":
		return uint64(value * 1024 * 1024 * 1024 * 1024), nil
	default:
		return 0, fmt.Errorf("unrecognized data unit")
	}
}

// Add additional types and methods as necessary below.

// FirmwareStatus represents the firmware status retrieved from OPNsense.
type FirmwareStatus struct {
	Status             string `json:"status"`
	DownloadSize       string `json:"download_size,omitempty"`
	Updates            int    `json:"new_packages_length"`
	NeedsReboot        string `json:"needs_reboot"`
	UpgradeNeedsReboot string `json:"upgrade_needs_reboot"`
	Connection         string `json:"connection"`
	Repository         string `json:"repository"`
	ProductLatest      string `json:"product_latest"`
	ProductVersion     string `json:"product_version"`
	StatusMsg          string `json:"status_msg,omitempty"`
}

// WireGuardStatus represents the WireGuard status retrieved from OPNsense.
type WireGuardStatus struct {
	Items map[string]struct {
		Instance  int    `json:"instance"`
		Interface string `json:"interface"`
		Enabled   int    `json:"enabled"`
		Name      string `json:"name"`
		Peers     map[string]struct {
			Name          string `json:"name"`
			Enabled       int    `json:"enabled"`
			PublicKey     string `json:"publicKey"`
			LastHandshake string `json:"lastHandshake"`
		} `json:"peers"`
	} `json:"items"`
}

// WireGuardInterface represents the configuration of a WireGuard interface.
type WireGuardInterface struct {
	Name          string
	PublicKey     string
	ListeningPort string
}

// WireGuardPeer represents a peer within a WireGuard interface.
type WireGuardPeer struct {
	Interface        string
	PublicKey        string
	TransferReceived uint64 // Stored as bytes
	TransferSent     uint64 // Stored as bytes
}
