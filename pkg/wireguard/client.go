package wireguard

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

const (
	timeLayout               = "2006-01-02 15:04:05-07:00"
	defaultHTTPClientTimeout = 10 * time.Second
	defaultGeoLiteDBPath     = "/opt/GeoLite2-Country.mmdb" // Default path to the MaxMind database
)

type Client struct {
	BaseURL    string
	APIKey     string
	APISecret  string
	HTTPClient *http.Client
	cache      map[string]string // Cache for country codes
	geoDB      *geoip2.Reader    // MaxMind GeoIP2 database
}

var (
	wgPeerTransferRxMetric      = newGaugeVec("wireguard_peer_transfer_rx_bytes", "Received bytes from the peer.", "interface", "peer_name", "public_key")
	wgPeerTransferTxMetric      = newGaugeVec("wireguard_peer_transfer_tx_bytes", "Sent bytes to the peer.", "interface", "peer_name", "public_key")
	wgPeerLatestHandshakeMetric = newGaugeVec("wireguard_peer_latest_handshake", "Latest handshake time with the peer as UNIX timestamp.", "interface", "peer_name", "public_key")
	wgPeerAllowedIPsMetric      = newGaugeVec("wireguard_peer_allowed_ips", "Allowed IPs for the WireGuard peer.", "interface", "peer_name", "public_key", "allowed_ip")
	wgPeerEndpointMetric        = newGaugeVec("wireguard_peer_endpoint", "Endpoint of the WireGuard peer.", "interface", "peer_name", "public_key", "endpoint_ip")
	wgPeerCountryCodeMetric     = newGaugeVec("wireguard_peer_country_code", "Country code of the WireGuard peer.", "interface", "peer_name", "public_key", "country_code")
	wgPeerHandshakeAgeMetric    = newGaugeVec("wireguard_peer_last_handshake_age_seconds", "Seconds since the peer's latest handshake.", "interface", "peer_name", "public_key")
	wgPeerKeepaliveMetric       = newGaugeVec("wireguard_peer_persistent_keepalive_seconds", "Persistent keepalive interval for the peer in seconds (0 if disabled).", "interface", "peer_name", "public_key")
	wgInterfaceStatusMetric     = newGaugeVec("wireguard_interface_status", "WireGuard interface status (1 = up, 0 = down).", "interface", "name")

	wgUpMetric            = prometheus.NewGauge(prometheus.GaugeOpts{Name: "wireguard_up", Help: "Whether the last scrape of the OPNsense API fully succeeded (1) or not (0)."})
	wgScrapeErrorsMetric  = prometheus.NewCounter(prometheus.CounterOpts{Name: "wireguard_scrape_errors_total", Help: "Total number of failed OPNsense API scrape cycles."})
	wgLastScrapeTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{Name: "wireguard_last_scrape_timestamp_seconds", Help: "Unix timestamp of the last fully successful scrape."})

	ifCollector = newInterfaceCollector()
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
		wgPeerHandshakeAgeMetric,
		wgPeerKeepaliveMetric,
		wgInterfaceStatusMetric,
		wgUpMetric,
		wgScrapeErrorsMetric,
		wgLastScrapeTimestamp,
		ifCollector,
	)

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	log.SetLevel(log.InfoLevel)
}

func NewClient(apiKey, apiSecret, baseURL string) (*Client, error) {
	// OPNsense commonly ships with a self-signed certificate, so certificate
	// verification is disabled by default. Set OPNSENSE_TLS_INSECURE=false to
	// enforce verification when a trusted certificate is in use.
	insecure := getEnvWithDefault("OPNSENSE_TLS_INSECURE", "true") != "false"
	if !insecure {
		log.Info("TLS certificate verification is enabled for OPNsense API requests")
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: insecure}

	client := &http.Client{
		Timeout: defaultHTTPClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// The GeoLite2 database is optional: if it cannot be opened, country-code
	// resolution is disabled (peers report country_code="unknown") but the
	// exporter still serves all other metrics.
	geoLiteDBPath := getEnvWithDefault("GEOLITE_DB_PATH", defaultGeoLiteDBPath)
	geoDB, err := geoip2.Open(geoLiteDBPath)
	if err != nil {
		log.WithError(err).Warnf("Could not open GeoLite2 database at %s; country-code resolution disabled", geoLiteDBPath)
		geoDB = nil
	}

	log.WithFields(log.Fields{"baseURL": baseURL}).Info("Connected to OPNsense")

	return &Client{
		BaseURL:    baseURL,
		APIKey:     apiKey,
		APISecret:  apiSecret,
		HTTPClient: client,
		cache:      make(map[string]string),
		geoDB:      geoDB,
	}, nil
}

// Close releases resources held by the client, in particular the GeoLite2
// database handle. It is safe to call on a nil geoDB.
func (c *Client) Close() error {
	if c.geoDB != nil {
		return c.geoDB.Close()
	}
	return nil
}

// recordSuccess marks the last scrape cycle as successful.
func (c *Client) recordSuccess() {
	wgUpMetric.Set(1)
	wgLastScrapeTimestamp.Set(float64(time.Now().Unix()))
}

// recordFailure marks the last scrape cycle as failed and increments the error counter.
func (c *Client) recordFailure() {
	wgUpMetric.Set(0)
	wgScrapeErrorsMetric.Inc()
}

// resetWireGuardMetrics clears all per-peer/per-interface WireGuard gauge series
// so that peers or endpoints that have disappeared since the previous cycle do
// not linger forever. It is called only on the success path, right before the
// gauges are repopulated with fresh data.
func resetWireGuardMetrics() {
	wgPeerTransferRxMetric.Reset()
	wgPeerTransferTxMetric.Reset()
	wgPeerLatestHandshakeMetric.Reset()
	wgPeerAllowedIPsMetric.Reset()
	wgPeerEndpointMetric.Reset()
	wgPeerCountryCodeMetric.Reset()
	wgPeerHandshakeAgeMetric.Reset()
	wgPeerKeepaliveMetric.Reset()
	wgInterfaceStatusMetric.Reset()
}

func (c *Client) UpdateMetrics() error {
	log.Println("Updating metrics...")

	// Update WireGuard metrics
	body, err := c.fetch("/api/wireguard/service/show")
	if err != nil {
		log.Errorf("Error fetching WireGuard configuration: %v", err)
		c.recordFailure()
		return err
	}

	var wgStatus WireGuardStatus
	err = json.Unmarshal(body, &wgStatus)
	if err != nil {
		log.Errorf("Failed to parse WireGuard config: %v", err)
		c.recordFailure()
		return fmt.Errorf("failed to parse WireGuard config: %v", err)
	}

	resetWireGuardMetrics()
	updateWireGuardMetrics(c, wgStatus.Rows)

	// Update interface metrics
	body, err = c.fetch("/api/diagnostics/traffic/interface")
	if err != nil {
		log.Errorf("Error fetching interface traffic data: %v", err)
		c.recordFailure()
		return err
	}

	var interfaceTraffic InterfaceTrafficStatus
	err = json.Unmarshal(body, &interfaceTraffic)
	if err != nil {
		log.Errorf("Failed to parse interface traffic data: %v", err)
		c.recordFailure()
		return fmt.Errorf("failed to parse interface traffic data: %v", err)
	}

	updateInterfaceMetrics(interfaceTraffic.Interfaces)

	c.recordSuccess()
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

	// Detect HTML responses (e.g. login/redirect page when using plain HTTP or with wrong credentials).
	// Trim leading whitespace before inspecting the first byte so that JSON with optional
	// leading whitespace is not mis-classified.
	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '<' {
		return nil, fmt.Errorf("API returned HTML instead of JSON for %s — verify that OPNSENSE_BASE_URL uses HTTPS and that API credentials are correct", endpoint)
	}

	return body, nil
}

func updateWireGuardMetrics(c *Client, rows []PeerStatus) {
	for _, row := range rows {
		switch row.Type {
		case "interface":
			status := 0.0
			if row.Status == "up" {
				status = 1
			}
			wgInterfaceStatusMetric.WithLabelValues(row.Ifname, row.Name).Set(status)
		case "peer":
			c.updatePeerMetrics(row)
		}
	}
}

func (c *Client) updatePeerMetrics(row PeerStatus) {
	wgPeerTransferRxMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(row.TransferRx))
	wgPeerTransferTxMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(row.TransferTx))
	wgPeerLatestHandshakeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(row.LatestHandshake))
	wgPeerKeepaliveMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(parseKeepalive(row.PersistentKeepalive))

	if row.LatestHandshakeAge != nil {
		wgPeerHandshakeAgeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey).Set(float64(*row.LatestHandshakeAge))
	}

	// One series per allowed IP so peers with multiple allowed-ips are fully represented.
	for _, allowedIP := range splitAllowedIPs(row.AllowedIPs) {
		wgPeerAllowedIPsMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, allowedIP).Set(1)
	}

	endpointIP := endpointHost(row.Endpoint)
	if endpointIP == "" {
		wgPeerCountryCodeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, "unknown").Set(1)
		return
	}

	wgPeerEndpointMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, endpointIP).Set(1)

	countryCode, err := c.getCountryCode(endpointIP)
	if err != nil {
		log.WithError(err).Errorf("Failed to get country code for IP %s", endpointIP)
		countryCode = "unknown"
	}
	wgPeerCountryCodeMetric.WithLabelValues(row.Ifname, row.Name, row.PublicKey, countryCode).Set(1)
}

func (c *Client) getCountryCode(ip string) (string, error) {
	if cc, found := c.cache[ip]; found {
		return cc, nil
	}

	if c.geoDB == nil {
		return "unknown", fmt.Errorf("GeoLite2 database not loaded")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "unknown", fmt.Errorf("invalid IP address: %s", ip)
	}

	record, err := c.geoDB.Country(parsedIP)
	if err != nil {
		return "unknown", fmt.Errorf("failed to get country code for IP %s: %v", ip, err)
	}

	c.cache[ip] = record.Country.IsoCode
	return record.Country.IsoCode, nil
}

func updateInterfaceMetrics(interfaces map[string]InterfaceData) {
	// Interface byte counters are exposed as proper Prometheus counters through
	// ifCollector, which emits them at scrape time from this snapshot.
	ifCollector.Update(interfaces)
}

func getEnvWithDefault(key string, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
