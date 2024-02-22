package wireguard

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

	// Настройка logrus
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	log.SetLevel(log.InfoLevel)

}

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
				// Handle the case where the last handshake time is not a valid date.
				// For example, you can set the metric to a default value like 0.
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
