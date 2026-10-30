package wireguard

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang/v2"
	"github.com/prometheus/client_golang/prometheus"
)

const defaultHTTPClientTimeout = 10 * time.Second

// Config holds everything NewClient needs.
type Config struct {
	BaseURL       string
	APIKey        string
	APISecret     string
	GeoLiteDBPath string
	TLSInsecure   bool
	CAFile        string
}

type Client struct {
	BaseURL    string
	APIKey     string
	APISecret  string
	HTTPClient *http.Client
	geoDB      *geoip2.Reader // MaxMind GeoIP2 database
}

var (
	wgUpMetric            = prometheus.NewGauge(prometheus.GaugeOpts{Name: "wireguard_up", Help: "Whether the last scrape of the OPNsense API fully succeeded (1) or not (0)."})
	wgScrapeErrorsMetric  = prometheus.NewCounter(prometheus.CounterOpts{Name: "wireguard_scrape_errors_total", Help: "Total number of failed OPNsense API scrape cycles."})
	wgLastScrapeTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{Name: "wireguard_last_scrape_timestamp_seconds", Help: "Unix timestamp of the last fully successful scrape."})

	wgCollector = &snapshotCollector{}
)

func init() {
	prometheus.MustRegister(
		wgUpMetric,
		wgScrapeErrorsMetric,
		wgLastScrapeTimestamp,
		wgCollector,
	)
}

// newTLSConfig trusts cfg.CAFile when set, which always keeps verification on.
// Otherwise cfg.TLSInsecure decides: OPNsense commonly ships with a self-signed
// certificate.
func newTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.CAFile == "" {
		if cfg.TLSInsecure {
			slog.Warn("TLS certificate verification is disabled for OPNsense API requests")
		}
		return &tls.Config{InsecureSkipVerify: cfg.TLSInsecure}, nil
	}

	pemData, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid PEM certificates in CA file %s", cfg.CAFile)
	}
	return &tls.Config{RootCAs: pool}, nil
}

// NewClient validates cfg and builds a client. It does not contact OPNsense.
func NewClient(cfg Config) (*Client, error) {
	if cfg.APIKey == "" || cfg.APISecret == "" {
		return nil, errors.New("OPNsense API key and secret are required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("OPNsense base URL must be an http or https URL with a host")
	}

	tlsConfig, err := newTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	client := &http.Client{
		Timeout:   defaultHTTPClientTimeout,
		Transport: transport,
	}

	// The GeoLite2 database is optional: if it cannot be opened, country-code
	// resolution is disabled (peers report country_code="unknown") but the
	// exporter still serves all other metrics.
	geoDB, err := geoip2.Open(cfg.GeoLiteDBPath)
	if err != nil {
		slog.Warn("Could not open GeoLite2 database; country-code resolution disabled", "path", cfg.GeoLiteDBPath, "error", err)
		geoDB = nil
	}

	return &Client{
		BaseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		APIKey:     cfg.APIKey,
		APISecret:  cfg.APISecret,
		HTTPClient: client,
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

// UpdateMetrics refreshes the exposed snapshot. The returned error is for the
// caller to log.
func (c *Client) UpdateMetrics(ctx context.Context) error {
	slog.Debug("Updating metrics")

	snapshot, err := c.scrape(ctx)
	if err != nil {
		c.recordFailure()
		return err
	}

	wgCollector.Update(snapshot)
	c.recordSuccess()
	slog.Debug("Metrics updated successfully")
	return nil
}

// scrape queries both API endpoints. Any failure discards the whole cycle, so
// the collector keeps its last complete snapshot.
func (c *Client) scrape(ctx context.Context) ([]prometheus.Metric, error) {
	body, err := c.fetch(ctx, "/api/wireguard/service/show")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch WireGuard status: %w", err)
	}

	var wgStatus WireGuardStatus
	if err := json.Unmarshal(body, &wgStatus); err != nil {
		return nil, fmt.Errorf("failed to parse WireGuard config: %w", err)
	}

	body, err = c.fetch(ctx, "/api/diagnostics/traffic/interface")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch interface traffic data: %w", err)
	}

	var interfaceTraffic InterfaceTrafficStatus
	if err := json.Unmarshal(body, &interfaceTraffic); err != nil {
		return nil, fmt.Errorf("failed to parse interface traffic data: %w", err)
	}

	return c.buildSnapshot(wgStatus.Rows, interfaceTraffic.Interfaces), nil
}

func (c *Client) fetch(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.APIKey, c.APISecret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Detect HTML responses (e.g. login/redirect page when using plain HTTP or with wrong credentials).
	// Trim leading whitespace before inspecting the first byte so that JSON with optional
	// leading whitespace is not mis-classified.
	if trimmed := bytes.TrimLeft(body, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '<' {
		return nil, fmt.Errorf("API returned HTML instead of JSON for %s — verify that OPNSENSE_BASE_URL uses HTTPS and that API credentials are correct", endpoint)
	}

	return body, nil
}

func (c *Client) getCountryCode(ip string) (string, error) {
	if c.geoDB == nil {
		return "unknown", nil
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "unknown", fmt.Errorf("invalid IP address: %w", err)
	}

	record, err := c.geoDB.Country(addr)
	if err != nil {
		return "unknown", fmt.Errorf("failed to get country code for IP %s: %w", ip, err)
	}

	if record.Country.ISOCode == "" {
		return "unknown", nil
	}
	return record.Country.ISOCode, nil
}
