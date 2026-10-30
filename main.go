package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"opnsense-wireguard-exporter/pkg/wireguard"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultMetricsUpdateIntervalSeconds = 30         // Default interval for metrics update in seconds
	defaultListenAddress                = ":9486"    // Default listen address for the server
	metricsEndpointPath                 = "/metrics" // Default metrics endpoint path
	defaultGeoLiteDBPath                = "/opt/GeoLite2-Country.mmdb"
	shutdownTimeout                     = 10 * time.Second
)

// version is overridable at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func getEnvWithDefault(key string, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// configFromEnv builds the client configuration. TLS verification stays off
// unless OPNSENSE_TLS_INSECURE=false, because OPNsense commonly ships with a
// self-signed certificate.
func configFromEnv() wireguard.Config {
	return wireguard.Config{
		BaseURL:       os.Getenv("OPNSENSE_BASE_URL"),
		APIKey:        os.Getenv("OPNSENSE_API_KEY"),
		APISecret:     os.Getenv("OPNSENSE_API_SECRET"),
		GeoLiteDBPath: getEnvWithDefault("GEOLITE_DB_PATH", defaultGeoLiteDBPath),
		TLSInsecure:   getEnvWithDefault("OPNSENSE_TLS_INSECURE", "true") != "false",
		CAFile:        os.Getenv("OPNSENSE_CA_FILE"),
	}
}

// parseUpdateInterval converts METRICS_UPDATE_INTERVAL_SECONDS into a duration
// that time.NewTicker accepts: positive and not overflowing time.Duration.
func parseUpdateInterval(raw string) (time.Duration, error) {
	seconds, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid METRICS_UPDATE_INTERVAL_SECONDS %q: %w", raw, err)
	}
	if seconds <= 0 || int64(seconds) > math.MaxInt64/int64(time.Second) {
		return 0, fmt.Errorf("invalid METRICS_UPDATE_INTERVAL_SECONDS %q: must be a positive number of seconds", raw)
	}
	return time.Duration(seconds) * time.Second, nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	slog.Info("Starting opnsense-wireguard-exporter", "version", version)

	updateInterval, err := parseUpdateInterval(getEnvWithDefault("METRICS_UPDATE_INTERVAL_SECONDS", strconv.Itoa(defaultMetricsUpdateIntervalSeconds)))
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	// Create a new OPNsense client
	client, err := wireguard.NewClient(configFromEnv())
	if err != nil {
		slog.Error("Error creating OPNsense client", "error", err)
		os.Exit(1)
	}
	defer func() {
		if cerr := client.Close(); cerr != nil {
			slog.Warn("Error closing client", "error", cerr)
		}
	}()

	// Root context cancelled on SIGINT/SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Metrics update loop
	var updateLoop sync.WaitGroup
	updateLoop.Go(func() { runUpdateLoop(ctx, client, updateInterval) })

	// Set up the HTTP server with sane timeouts (mitigates Slowloris-style attacks).
	listenAddress := getEnvWithDefault("LISTEN_ADDRESS", defaultListenAddress)
	metricsPath := getEnvWithDefault("METRICS_ENDPOINT_PATH", metricsEndpointPath)

	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("Beginning to serve", "address", listenAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Block until a shutdown signal is received.
	<-ctx.Done()
	slog.Info("Shutdown signal received, stopping server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("Graceful shutdown failed", "error", err)
	}

	// The deferred client.Close must not run while a GeoIP lookup is in progress.
	updateLoop.Wait()
	slog.Info("Server stopped")
}

// runUpdateLoop refreshes metrics on a fixed interval until the context is cancelled.
func runUpdateLoop(ctx context.Context, client *wireguard.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Update immediately on startup rather than waiting for the first tick.
	update := func() {
		// An update aborted by shutdown is not a failed cycle worth reporting.
		if err := client.UpdateMetrics(ctx); err != nil && ctx.Err() == nil {
			slog.Error("Error updating metrics", "error", err)
		}
	}
	update()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		}
	}
}
