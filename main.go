package main

import (
	"net/http"
	"time"

	"opnsense-wireguard-exporter/pkg/wireguard"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Настройка клиента
	apiKey := ""    // Замените на ваш API ключ
	apiSecret := "" // Замените на ваш API секрет
	baseURL := ""   // Замените на ваш базовый URL

	client, err := wireguard.NewClient(apiKey, apiSecret, baseURL)
	if err != nil {
		log.Fatalf("Error creating OPNsense client: %v", err)
	}

	// Цикл обновления метрик
	go func() {
		for {
			if err := client.UpdateMetrics(); err != nil {
				log.WithError(err).Error("Error updating metrics")
			}
			time.Sleep(30 * time.Second)
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	log.Info("Beginning to serve on port :9100")
	if err := http.ListenAndServe(":9100", nil); err != nil {
		log.WithError(err).Fatal("Server failed")
	}
}
