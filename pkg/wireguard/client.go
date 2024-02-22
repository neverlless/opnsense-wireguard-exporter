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

	prometheus "github.com/prometheus/client_golang/prometheus"

	log "github.com/sirupsen/logrus"
)

// Client структура для взаимодействия с OPNsense API
type Client struct {
	BaseURL    string
	APIKey     string
	APISecret  string
	HTTPClient *http.Client
}

// Определим метрику Prometheus для количества доступных обновлений
var (
	needsRebootMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "opnsense_firmware_needs_reboot",
		Help: "Indicates if a reboot is required after firmware updates",
	})
	connectionStatusMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "opnsense_firmware_connection_status",
		Help: "Status of the connection to the firmware repository",
	}, []string{"status"})
	repositoryStatusMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "opnsense_firmware_repository_status",
		Help: "Status of the firmware repository",
	}, []string{"status"})
	productVersionMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "opnsense_product_version_info",
		Help: "The current version of the OPNsense product",
	}, []string{"version"})
	wgPeerLastHandshakeMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wireguard_peer_last_handshake_seconds",
		Help: "Last handshake time with the peer as UNIX timestamp.",
	}, []string{"interface", "peer_name", "public_key"})

	wgPeerStatusMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wireguard_peer_status",
		Help: "Status of the WireGuard peer (enabled/disabled).",
	}, []string{"interface", "peer_name", "public_key"})
	wgTotalPeersMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "wireguard_total_peers",
		Help: "Total number of WireGuard peers.",
	})
	wgInterfaceInfoMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wireguard_interface_info",
		Help: "Information about the WireGuard interface.",
	}, []string{"interface", "public_key", "listening_port"})

	wgPeerTransferMetric = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "wireguard_peer_transfer_bytes",
		Help: "Number of bytes transferred to and from the peer.",
	}, []string{"interface", "peer_public_key", "direction"}) // direction can be "received" or "sent"
)

func init() {
	// Регистрация новых метрик в Prometheus
	prometheus.MustRegister(needsRebootMetric)
	prometheus.MustRegister(connectionStatusMetric)
	prometheus.MustRegister(repositoryStatusMetric)
	prometheus.MustRegister(productVersionMetric)
	prometheus.MustRegister(wgPeerLastHandshakeMetric)
	prometheus.MustRegister(wgPeerStatusMetric)
	prometheus.MustRegister(wgTotalPeersMetric)
	prometheus.MustRegister(wgInterfaceInfoMetric)
	prometheus.MustRegister(wgPeerTransferMetric)

	// Настройка logrus
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	log.SetLevel(log.InfoLevel)

}

// FetchWireGuardConfig fetches the WireGuard configuration from the endpoint
func (c *Client) FetchWireGuardConfig() error {
	log.Println("Fetching WireGuard configuration...")
	body, err := c.fetch("/api/wireguard/service/showconf")
	if err != nil {
		log.Printf("Error fetching WireGuard configuration: %v\n", err)
		return err
	}

	interfaces, peers, err := parseWireGuardConfig(body)
	if err != nil {
		log.Printf("Failed to parse WireGuard config: %v\n", err)
		return fmt.Errorf("failed to parse WireGuard config: %v", err)
	}

	log.Println("Updating WireGuard metrics...")
	for _, intf := range interfaces {
		wgInterfaceInfoMetric.WithLabelValues(
			intf.Name,
			intf.PublicKey,
			intf.ListeningPort,
		).Set(1) // Используем WithLabelValues вместо With
	}

	for _, peer := range peers {
		wgPeerTransferMetric.WithLabelValues(
			peer.Interface,
			peer.PublicKey,
			"received",
		).Set(float64(peer.TransferReceived))

		wgPeerTransferMetric.WithLabelValues(
			peer.Interface,
			peer.PublicKey,
			"sent",
		).Set(float64(peer.TransferSent))
	}

	log.Println("WireGuard metrics updated successfully.")
	return nil
}

// UpdateMetrics обновляет метрики, получая статусы прошивки и WireGuard
func (c *Client) UpdateMetrics() error {
	firmwareStatus, err := c.FetchFirmwareStatus()
	if err != nil {
		return err
	}

	// Устанавливаем значения для новых метрик
	needsReboot, _ := strconv.ParseFloat(firmwareStatus.NeedsReboot, 64)
	needsRebootMetric.Set(needsReboot)

	connectionStatusMetric.With(prometheus.Labels{"status": firmwareStatus.Connection}).Set(1)
	repositoryStatusMetric.With(prometheus.Labels{"status": firmwareStatus.Repository}).Set(1)

	productVersionMetric.With(prometheus.Labels{"version": firmwareStatus.ProductVersion}).Set(1) // Установка версии продукта

	wgStatus, err := c.FetchWireGuardStatus()
	if err != nil {
		return err
	}

	totalPeers := 0 // Initialize a counter for the total number of peers

	for _, wg := range wgStatus.Items {
		for _, peer := range wg.Peers {
			if peer.LastHandshake != "0000-00-00 00:00:00+00:00" {
				lastHandshakeTime, err := time.Parse("2006-01-02 15:04:05-07:00", peer.LastHandshake)
				if err != nil {
					log.WithError(err).Error("Failed to parse last handshake time")
					continue
				}
				wgPeerLastHandshakeMetric.With(prometheus.Labels{
					"interface":  wg.Interface,
					"peer_name":  peer.Name,
					"public_key": peer.PublicKey,
				}).Set(float64(lastHandshakeTime.Unix()))
			} else {
				wgPeerLastHandshakeMetric.With(prometheus.Labels{
					"interface":  wg.Interface,
					"peer_name":  peer.Name,
					"public_key": peer.PublicKey,
				}).Set(0)
			}

			wgPeerStatusMetric.With(prometheus.Labels{
				"interface":  wg.Interface,
				"peer_name":  peer.Name,
				"public_key": peer.PublicKey,
			}).Set(float64(peer.Enabled))

			totalPeers++
		}
	}

	// Set the total number of peers metric
	wgTotalPeersMetric.Set(float64(totalPeers))

	// Update the WireGuard configuration
	if err := c.FetchWireGuardConfig(); err != nil {
		return err
	}
	return nil
}

// FetchWireGuardStatus fetches the WireGuard status from the endpoint
func (c *Client) FetchWireGuardStatus() (*WireGuardStatus, error) {
	body, err := c.fetch("/api/wireguard/general/getStatus")
	if err != nil {
		return nil, err
	}

	var status WireGuardStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal WireGuard status: %v", err)
	}

	return &status, nil
}

// NewClient создает новый клиент для OPNsense API
func NewClient(apiKey, apiSecret, baseURL string) (*Client, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Добавляем эту опцию для игнорирования проверки валидности сертификата
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	log.WithFields(log.Fields{"baseURL": baseURL}).Info("Connected to OPNsense")

	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		APISecret:  apiSecret,
		HTTPClient: client,
	}, nil

}

// fetch выполняет запрос к API и возвращает результат
func (c *Client) fetch(endpoint string) ([]byte, error) {
	req, err := http.NewRequest("GET", c.BaseURL+endpoint, nil)
	if err != nil {
		log.WithError(err).Error("Failed to perform request")
	}

	req.SetBasicAuth(c.APIKey, c.APISecret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.WithError(err).Error("Failed to perform request")
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

// FetchFirmwareStatus получает статус прошивки из OPNsense
func (c *Client) FetchFirmwareStatus() (*FirmwareStatus, error) {
	body, err := c.fetch("/api/core/firmware/status")
	if err != nil {
		return nil, err
	}

	var status FirmwareStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to unmarshal firmware status: %v", err)
	}

	return &status, nil
}

// FirmwareStatus структура для хранения статуса прошивки
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
type WireGuardInterface struct {
	Name          string
	PublicKey     string
	ListeningPort string
}

type WireGuardPeer struct {
	Interface        string
	PublicKey        string
	TransferReceived uint64 // Store as bytes
	TransferSent     uint64 // Store as bytes
}

// parseWireGuardConfig parses the WireGuard configuration
func parseWireGuardConfig(config []byte) ([]WireGuardInterface, []WireGuardPeer, error) {
	var wgConf struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(config, &wgConf); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	lines := strings.Split(wgConf.Response, "\n")

	var interfaces []WireGuardInterface
	var peers []WireGuardPeer
	var currentInterface string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, "interface:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				currentInterface = fields[1]
				interfaces = append(interfaces, WireGuardInterface{Name: currentInterface})
			}
		case strings.HasPrefix(line, "public key:"):
			fields := strings.Fields(line)
			if len(fields) >= 3 && len(interfaces) > 0 {
				interfaces[len(interfaces)-1].PublicKey = fields[2]
			}
		case strings.HasPrefix(line, "listening port:"):
			fields := strings.Fields(line)
			if len(fields) >= 3 && len(interfaces) > 0 {
				interfaces[len(interfaces)-1].ListeningPort = fields[2]
			}
		case strings.HasPrefix(line, "peer:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				peers = append(peers, WireGuardPeer{
					Interface: currentInterface,
					PublicKey: fields[1],
				})
			}
		case strings.HasPrefix(line, "transfer:"):
			fields := strings.Fields(line)
			if len(fields) >= 5 && len(peers) > 0 {
				receivedBytes, err := parseTransfer(fields[1] + " " + fields[2])
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse received data: %v", err)
				}
				sentBytes, err := parseTransfer(fields[4] + " " + fields[5])
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse sent data: %v", err)
				}
				peers[len(peers)-1].TransferReceived = receivedBytes
				peers[len(peers)-1].TransferSent = sentBytes
			}
		}
	}

	return interfaces, peers, nil
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
