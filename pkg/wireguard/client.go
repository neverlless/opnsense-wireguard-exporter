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
)

func init() {
	// Регистрация новых метрик в Prometheus
	prometheus.MustRegister(needsRebootMetric)
	prometheus.MustRegister(connectionStatusMetric)
	prometheus.MustRegister(repositoryStatusMetric)
	prometheus.MustRegister(productVersionMetric)

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

	return nil
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
