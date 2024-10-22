package wireguard

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

const (
	timeLayout               = "2006-01-02 15:04:05-07:00"
	defaultHTTPClientTimeout = 10 * time.Second
	apiRateLimit             = 45               // 45 requests per minute
	apiRateInterval          = time.Minute / 45 // interval between requests
)

type Client struct {
	BaseURL    string
	APIKey     string
	APISecret  string
	HTTPClient *http.Client
	limiter    *rate.Limiter
	cache      map[string]string // Cache for country codes
}

var (
	wgPeerTransferRxMetric          = newGaugeVec("wireguard_peer_transfer_rx_bytes", "Received bytes from the peer.", "interface", "peer_name", "public_key")
	wgPeerTransferTxMetric          = newGaugeVec("wireguard_peer_transfer_tx_bytes", "Sent bytes to the peer.", "interface", "peer_name", "public_key")
	wgPeerLatestHandshakeMetric     = newGaugeVec("wireguard_peer_latest_handshake", "Latest handshake time with the peer as UNIX timestamp.", "interface", "peer_name", "public_key")
	wgPeerAllowedIPsMetric          = newGaugeVec("wireguard_peer_allowed_ips", "Allowed IPs for the WireGuard peer.", "interface", "peer_name", "public_key", "allowed_ip")
	wgPeerEndpointMetric            = newGaugeVec("wireguard_peer_endpoint", "Endpoint of the WireGuard peer.", "interface", "peer_name", "public_key", "endpoint_ip")
	wgPeerCountryCodeMetric         = newGaugeVec("wireguard_peer_country_code", "Country code of the WireGuard peer.", "interface", "peer_name", "public_key", "country_code")
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
		wgPeerCountryCodeMetric,
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

	limiter := rate.NewLimiter(rate.Every(apiRateInterval), 1)

	log.WithFields(log.Fields{"baseURL": baseURL}).Info("Connected to OPNsense")

	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		APISecret:  apiSecret,
		HTTPClient: client,
		limiter:    limiter,
		cache:      make(map[string]string), // Cache for country codes
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

	updateWireGuardMetrics(c, wgStatus.Rows)

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

func updateWireGuardMetrics(c *Client, rows []PeerStatus) {
	// Create a queue of IP addresses and a map to store peer information
	ipQueue := make([]string, 0)
	ipInfo := make(map[string]PeerStatus)

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

			// Check if endpointIP is valid before querying
			if endpointIP != "" && endpointIP != "(none)" {
				// Add IP to queue and save peer information
				ipQueue = append(ipQueue, endpointIP)
				ipInfo[endpointIP] = row
			} else {
				// log.Warnf("Invalid endpoint IP for peer %s: %s", row.Name, endpointIP)
				wgPeerCountryCodeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, "unknown").Set(1)
			}
		}
	}

	// Process part of the queue to avoid exceeding the limit
	for _, ip := range ipQueue[:min(len(ipQueue), apiRateLimit)] {
		row := ipInfo[ip]
		// Check cache before querying
		if countryCode, found := c.cache[ip]; found {
			log.Infof("Cache hit for IP: %s, country code: %s", ip, countryCode)
			wgPeerCountryCodeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, countryCode).Set(1)
			continue
		}

		log.Infof("Attempting to query country code for IP: %s", ip)
		// Get country code from endpoint IP
		countryCode, err := c.getCountryCode(ip)
		if err != nil {
			log.WithError(err).Errorf("Failed to get country code for IP %s", ip)
			wgPeerCountryCodeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, "unknown").Set(1)
		} else {
			log.Infof("Country code for IP %s is %s", ip, countryCode)
			wgPeerCountryCodeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, countryCode).Set(1)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *Client) getCountryCode(ip string) (string, error) {
	if !c.limiter.Allow() {
		log.Warnf("Rate limit exceeded, skipping IP: %s", ip)
		c.cache[ip] = "unknown"
		return "unknown", nil
	}

	log.Infof("Sending request to ip-api.com for IP: %s", ip)
	resp, err := c.HTTPClient.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil {
		log.WithError(err).Errorf("HTTP request failed for IP %s", ip)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Received non-OK HTTP status %d for IP %s", resp.StatusCode, ip)
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		CountryCode string `json:"countryCode"`
		Status      string `json:"status"`
		Message     string `json:"message"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		log.WithError(err).Errorf("Failed to decode JSON response for IP %s", ip)
		return "", err
	}

	if result.Status != "success" {
		log.Warnf("Failed to get country code for IP %s: %s", ip, result.Message)
		c.cache[ip] = "unknown"
		return "unknown", nil
	}

	c.cache[ip] = result.CountryCode // Save to cache
	return result.CountryCode, nil
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
