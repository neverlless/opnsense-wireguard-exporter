package main

import (
	"net/http"
	"os"
	"time"

	"opnsense-wireguard-exporter/pkg/wireguard"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMetricsUpdateInterval = 30 * time.Second // Interval for metrics update
	defaultListenAddress         = ":9100"          // Default listen address for the server
)

func main() {
	// Client configuration
	apiKey := os.Getenv("OPNSENSE_API_KEY")       // Replace with your API key from environment variable
	apiSecret := os.Getenv("OPNSENSE_API_SECRET") // Replace with your API secret from environment variable
	baseURL := os.Getenv("OPNSENSE_BASE_URL")     // Replace with your base URL from environment variable

	// Create a new OPNsense client
	client, err := wireguard.NewClient(apiKey, apiSecret, baseURL)
	if err != nil {
		log.Fatalf("Error creating OPNsense client: %v", err)
	}

	// Metrics update loop
	go func() {
		for {
			if err := client.UpdateMetrics(); err != nil {
				log.WithError(err).Error("Error updating metrics")
			}
			time.Sleep(defaultMetricsUpdateInterval)
		}
	}()

	// Set up Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())
	log.Infof("Beginning to serve on port %s", defaultListenAddress)
	if err := http.ListenAndServe(defaultListenAddress, nil); err != nil {
		log.WithError(err).Fatal("Server failed")
	}
}
