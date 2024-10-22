package main

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"opnsense-wireguard-exporter/pkg/wireguard"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMetricsUpdateIntervalSeconds = 30         // Default interval for metrics update in seconds
	defaultListenAddress                = ":9486"    // Default listen address for the server
	metricsEndpointPath                 = "/metrics" // Default metrics endpoint path
)

func getEnvWithDefault(key string, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func main() {
	// Client configuration
	apiKey := os.Getenv("OPNSENSE_API_KEY")
	apiSecret := os.Getenv("OPNSENSE_API_SECRET")
	baseURL := os.Getenv("OPNSENSE_BASE_URL")

	// Create a new OPNsense client
	client, err := wireguard.NewClient(apiKey, apiSecret, baseURL)
	if err != nil {
		log.Fatalf("Error creating OPNsense client: %v", err)
	}

	// Metrics update loop
	updateIntervalSeconds := getEnvWithDefault("METRICS_UPDATE_INTERVAL_SECONDS", strconv.Itoa(defaultMetricsUpdateIntervalSeconds))
	updateInterval, err := strconv.Atoi(updateIntervalSeconds)
	if err != nil {
		log.Fatalf("Invalid METRICS_UPDATE_INTERVAL_SECONDS: %v", err)
	}
	go func() {
		for {
			if err := client.UpdateMetrics(); err != nil {
				log.WithError(err).Error("Error updating metrics")
			}
			time.Sleep(time.Duration(updateInterval) * time.Second)
		}
	}()

	// Set up Prometheus metrics endpoint
	listenAddress := getEnvWithDefault("LISTEN_ADDRESS", defaultListenAddress)
	metricsPath := getEnvWithDefault("METRICS_ENDPOINT_PATH", metricsEndpointPath)
	http.Handle(metricsPath, promhttp.Handler())
	log.Infof("Beginning to serve on port %s", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		log.WithError(err).Fatal("Server failed")
	}
}
