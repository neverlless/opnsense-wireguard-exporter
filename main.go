package main

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"opnsense-wireguard-exporter/pkg/wireguard"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMetricsUpdateIntervalSeconds = 30         // Default interval for metrics update in seconds
	defaultListenAddress                = ":9486"    // Default listen address for the server
	metricsEndpointPath                 = "/metrics" // Default metrics endpoint path
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
	log.Infof("Starting opnsense-wireguard-exporter %s", version)

	// Client configuration
	apiKey := os.Getenv("OPNSENSE_API_KEY")
	apiSecret := os.Getenv("OPNSENSE_API_SECRET")
	baseURL := os.Getenv("OPNSENSE_BASE_URL")

	// Create a new OPNsense client
	client, err := wireguard.NewClient(apiKey, apiSecret, baseURL)
	if err != nil {
		log.Fatalf("Error creating OPNsense client: %v", err)
	}
	defer func() {
		if cerr := client.Close(); cerr != nil {
			log.WithError(cerr).Warn("Error closing client")
		}
	}()

	// Root context cancelled on SIGINT/SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Metrics update loop
	updateInterval, err := parseUpdateInterval(getEnvWithDefault("METRICS_UPDATE_INTERVAL_SECONDS", strconv.Itoa(defaultMetricsUpdateIntervalSeconds)))
	if err != nil {
		log.Fatal(err)
	}
	go runUpdateLoop(ctx, client, updateInterval)

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
		log.Infof("Beginning to serve on %s", listenAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Server failed")
		}
	}()

	// Block until a shutdown signal is received.
	<-ctx.Done()
	log.Info("Shutdown signal received, stopping server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Error("Graceful shutdown failed")
	}
	log.Info("Server stopped")
}

// runUpdateLoop refreshes metrics on a fixed interval until the context is cancelled.
func runUpdateLoop(ctx context.Context, client *wireguard.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Update immediately on startup rather than waiting for the first tick.
	if err := client.UpdateMetrics(); err != nil {
		log.WithError(err).Error("Error updating metrics")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := client.UpdateMetrics(); err != nil {
				log.WithError(err).Error("Error updating metrics")
			}
		}
	}
}
