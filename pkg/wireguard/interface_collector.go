package wireguard

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// interfaceCollector exposes per-interface byte totals as proper Prometheus
// counters. The values originate from OPNsense as absolute cumulative numbers,
// so they are emitted via ConstMetric at scrape time from the latest snapshot
// rather than via a settable gauge. This keeps the "_total" naming semantically
// correct while remaining safe for concurrent scrape/update access.
type interfaceCollector struct {
	mu       sync.RWMutex
	snapshot map[string]InterfaceData

	rxDesc *prometheus.Desc
	txDesc *prometheus.Desc
}

func newInterfaceCollector() *interfaceCollector {
	labels := []string{"interface", "device", "name"}
	return &interfaceCollector{
		rxDesc: prometheus.NewDesc("interfaces_received_bytes_total", "Total bytes received by the interface.", labels, nil),
		txDesc: prometheus.NewDesc("interfaces_transmitted_bytes_total", "Total bytes transmitted by the interface.", labels, nil),
	}
}

// Update replaces the snapshot used for the next scrape.
func (c *interfaceCollector) Update(interfaces map[string]InterfaceData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = interfaces
}

func (c *interfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rxDesc
	ch <- c.txDesc
}

func (c *interfaceCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()

	for name, data := range snapshot {
		if rx, err := strconv.ParseInt(data.BytesReceived, 10, 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.rxDesc, prometheus.CounterValue, float64(rx), name, data.Device, data.Name)
		} else {
			log.WithError(err).Errorf("Failed to parse bytes received for interface %s", name)
		}

		if tx, err := strconv.ParseInt(data.BytesTransmitted, 10, 64); err == nil {
			ch <- prometheus.MustNewConstMetric(c.txDesc, prometheus.CounterValue, float64(tx), name, data.Device, data.Name)
		} else {
			log.WithError(err).Errorf("Failed to parse bytes transmitted for interface %s", name)
		}
	}
}
