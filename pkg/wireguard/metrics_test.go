package wireguard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func int64ptr(v int64) *int64 { return &v }

// TestUpdatePeerMetrics_IPv6AndAllowedIPs verifies IPv6 endpoint parsing, that
// every allowed IP produces its own series, and keepalive/handshake-age metrics.
func TestUpdatePeerMetrics_IPv6AndAllowedIPs(t *testing.T) {
	resetWireGuardMetrics()
	c := &Client{cache: make(map[string]string)}

	rows := []PeerStatus{{
		Type:                "peer",
		Ifname:              "wg0",
		Name:                "alice",
		PublicKey:           "PK1",
		Endpoint:            "[2001:db8::1]:51820",
		AllowedIPs:          "10.0.0.2/32,10.0.0.3/32",
		PersistentKeepalive: "25",
		LatestHandshakeAge:  int64ptr(42),
	}}
	updateWireGuardMetrics(c, rows)

	if got := testutil.ToFloat64(wgPeerEndpointMetric.WithLabelValues("wg0", "alice", "PK1", "2001:db8::1")); got != 1 {
		t.Errorf("endpoint metric for IPv6 host = %v, want 1", got)
	}
	if n := testutil.CollectAndCount(wgPeerAllowedIPsMetric); n != 2 {
		t.Errorf("allowed-ips series count = %d, want 2", n)
	}
	if got := testutil.ToFloat64(wgPeerKeepaliveMetric.WithLabelValues("wg0", "alice", "PK1")); got != 25 {
		t.Errorf("keepalive = %v, want 25", got)
	}
	if got := testutil.ToFloat64(wgPeerHandshakeAgeMetric.WithLabelValues("wg0", "alice", "PK1")); got != 42 {
		t.Errorf("handshake age = %v, want 42", got)
	}
}

// TestUpdateWireGuardMetrics_InterfaceStatus verifies interface up/down status.
func TestUpdateWireGuardMetrics_InterfaceStatus(t *testing.T) {
	resetWireGuardMetrics()
	c := &Client{cache: make(map[string]string)}

	rows := []PeerStatus{
		{Type: "interface", Ifname: "wg0", Name: "WG Server", Status: "up"},
		{Type: "interface", Ifname: "wg1", Name: "WG Backup", Status: "down"},
	}
	updateWireGuardMetrics(c, rows)

	if got := testutil.ToFloat64(wgInterfaceStatusMetric.WithLabelValues("wg0", "WG Server")); got != 1 {
		t.Errorf("wg0 status = %v, want 1", got)
	}
	if got := testutil.ToFloat64(wgInterfaceStatusMetric.WithLabelValues("wg1", "WG Backup")); got != 0 {
		t.Errorf("wg1 status = %v, want 0", got)
	}
}

// TestResetWireGuardMetrics verifies stale series are cleared on reset.
func TestResetWireGuardMetrics(t *testing.T) {
	resetWireGuardMetrics()
	c := &Client{cache: make(map[string]string)}
	updateWireGuardMetrics(c, []PeerStatus{{
		Type: "peer", Ifname: "wg0", Name: "bob", PublicKey: "PK2",
		Endpoint: "1.2.3.4:51820", AllowedIPs: "10.0.0.5/32",
	}})
	if n := testutil.CollectAndCount(wgPeerTransferRxMetric); n != 1 {
		t.Fatalf("rx series before reset = %d, want 1", n)
	}
	resetWireGuardMetrics()
	if n := testutil.CollectAndCount(wgPeerTransferRxMetric); n != 0 {
		t.Errorf("rx series after reset = %d, want 0", n)
	}
}

// TestUpdateMetrics_FailureSetsDown verifies wireguard_up drops to 0 and the
// error counter increments when the API call fails.
func TestUpdateMetrics_FailureSetsDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := newTestClient(server)
	wgUpMetric.Set(1)
	before := testutil.ToFloat64(wgScrapeErrorsMetric)

	if err := c.UpdateMetrics(); err == nil {
		t.Fatal("expected error from failing API, got nil")
	}
	if got := testutil.ToFloat64(wgUpMetric); got != 0 {
		t.Errorf("wireguard_up = %v, want 0 after failure", got)
	}
	if after := testutil.ToFloat64(wgScrapeErrorsMetric); after != before+1 {
		t.Errorf("scrape errors = %v, want %v", after, before+1)
	}
}

// TestInterfaceCollector verifies interface byte counters are emitted from the snapshot.
func TestInterfaceCollector(t *testing.T) {
	col := newInterfaceCollector()
	col.Update(map[string]InterfaceData{
		"lan": {Device: "igb0", Name: "LAN", BytesReceived: "1000", BytesTransmitted: "2000"},
	})
	if n := testutil.CollectAndCount(col); n != 2 {
		t.Errorf("interface collector series = %d, want 2", n)
	}
}
