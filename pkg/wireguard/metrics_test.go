package wireguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func int64ptr(v int64) *int64 { return &v }

// Realistic trimmed responses of the OPNsense API.
const (
	wgShowJSON = `{"total":3,"rowCount":3,"current":1,"rows":[
		{"if":"wg0","type":"interface","private-key":"(hidden)","public-key":"SRV","listen-port":"51820","fwmark":"off",
		 "status":"up","name":"WG Server","ifname":"wg0"},
		{"if":"wg0","type":"peer","public-key":"PK1","preshared-key":"(hidden)","endpoint":"[2001:db8::1]:51820",
		 "allowed-ips":"10.0.0.0/24,fd00::2/128","latest-handshake":1761800000,"transfer-rx":1000,"transfer-tx":2000,
		 "persistent-keepalive":"25","latest-handshake-age":42,"peer-status":"online","name":"alice","ifname":"wg0"},
		{"if":"wg0","type":"peer","public-key":"PK2","preshared-key":"(none)","endpoint":"(none)",
		 "allowed-ips":"(none)","latest-handshake":0,"transfer-rx":0,"transfer-tx":0,
		 "persistent-keepalive":"off","latest-handshake-age":null,"peer-status":"offline","name":"bob","ifname":"wg0"}
	]}`
	trafficJSON = `{"interfaces":{"lan":{"device":"igb0","driver":"igb","mtu":"1500","packets received":"12",
		"bytes received":"1000","bytes transmitted":"2000","link state":"2","name":"LAN"}},"time":1761800000.12}`
)

// metricsHeader carries HELP/TYPE for every snapshot metric. Families without
// samples are ignored by the comparison, so test cases only list their series.
const metricsHeader = `
# HELP interfaces_received_bytes_total Total bytes received by the interface.
# TYPE interfaces_received_bytes_total counter
# HELP interfaces_transmitted_bytes_total Total bytes transmitted by the interface.
# TYPE interfaces_transmitted_bytes_total counter
# HELP wireguard_interface_status WireGuard interface status (1 = up, 0 = down).
# TYPE wireguard_interface_status gauge
# HELP wireguard_peer_allowed_ips Allowed IPs for the WireGuard peer.
# TYPE wireguard_peer_allowed_ips gauge
# HELP wireguard_peer_country_code Country code of the WireGuard peer.
# TYPE wireguard_peer_country_code gauge
# HELP wireguard_peer_endpoint Endpoint of the WireGuard peer.
# TYPE wireguard_peer_endpoint gauge
# HELP wireguard_peer_last_handshake_age_seconds Seconds since the peer's latest handshake.
# TYPE wireguard_peer_last_handshake_age_seconds gauge
# HELP wireguard_peer_latest_handshake Latest handshake time with the peer as UNIX timestamp.
# TYPE wireguard_peer_latest_handshake gauge
# HELP wireguard_peer_persistent_keepalive_seconds Persistent keepalive interval for the peer in seconds (0 if disabled).
# TYPE wireguard_peer_persistent_keepalive_seconds gauge
# HELP wireguard_peer_transfer_rx_bytes_total Received bytes from the peer.
# TYPE wireguard_peer_transfer_rx_bytes_total counter
# HELP wireguard_peer_transfer_tx_bytes_total Sent bytes to the peer.
# TYPE wireguard_peer_transfer_tx_bytes_total counter
`

// snapshotMetricNames lists every metric replaced on a successful update.
var snapshotMetricNames = []string{
	"interfaces_received_bytes_total",
	"interfaces_transmitted_bytes_total",
	"wireguard_interface_status",
	"wireguard_peer_allowed_ips",
	"wireguard_peer_country_code",
	"wireguard_peer_endpoint",
	"wireguard_peer_last_handshake_age_seconds",
	"wireguard_peer_latest_handshake",
	"wireguard_peer_persistent_keepalive_seconds",
	"wireguard_peer_transfer_rx_bytes_total",
	"wireguard_peer_transfer_tx_bytes_total",
}

// assertExposed compares the snapshot metrics of gatherer with series.
func assertExposed(t *testing.T, gatherer prometheus.Gatherer, series string) {
	t.Helper()
	expected := strings.NewReader(metricsHeader + series)
	if err := testutil.GatherAndCompare(gatherer, expected, snapshotMetricNames...); err != nil {
		t.Error(err)
	}
}

// newAPIServer fakes the two OPNsense endpoints; an empty body responds with 500.
func newAPIServer(t *testing.T, wgBody, trafficBody string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, pass, ok := r.BasicAuth(); !ok || user != "test-key" || pass != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body := map[string]string{
			"/api/wireguard/service/show":        wgBody,
			"/api/diagnostics/traffic/interface": trafficBody,
		}[r.URL.Path]
		if body == "" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUpdateMetrics_Success verifies the whole update path, from the API
// responses to what the default registry exposes.
func TestUpdateMetrics_Success(t *testing.T) {
	cases := []struct {
		name        string
		wgBody      string
		trafficBody string
		want        string
	}{
		{
			name:        "interface, connected peer, never connected peer",
			wgBody:      wgShowJSON,
			trafficBody: trafficJSON,
			want: `
interfaces_received_bytes_total{device="igb0",interface="lan",name="LAN"} 1000
interfaces_transmitted_bytes_total{device="igb0",interface="lan",name="LAN"} 2000
wireguard_interface_status{interface="wg0",name="WG Server"} 1
wireguard_peer_allowed_ips{allowed_ip="10.0.0.0/24",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_allowed_ips{allowed_ip="fd00::2/128",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_country_code{country_code="unknown",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_country_code{country_code="unknown",interface="wg0",peer_name="bob",public_key="PK2"} 1
wireguard_peer_endpoint{endpoint_ip="2001:db8::1",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_last_handshake_age_seconds{interface="wg0",peer_name="alice",public_key="PK1"} 42
wireguard_peer_latest_handshake{interface="wg0",peer_name="alice",public_key="PK1"} 1.7618e+09
wireguard_peer_latest_handshake{interface="wg0",peer_name="bob",public_key="PK2"} 0
wireguard_peer_persistent_keepalive_seconds{interface="wg0",peer_name="alice",public_key="PK1"} 25
wireguard_peer_persistent_keepalive_seconds{interface="wg0",peer_name="bob",public_key="PK2"} 0
wireguard_peer_transfer_rx_bytes_total{interface="wg0",peer_name="alice",public_key="PK1"} 1000
wireguard_peer_transfer_rx_bytes_total{interface="wg0",peer_name="bob",public_key="PK2"} 0
wireguard_peer_transfer_tx_bytes_total{interface="wg0",peer_name="alice",public_key="PK1"} 2000
wireguard_peer_transfer_tx_bytes_total{interface="wg0",peer_name="bob",public_key="PK2"} 0
`,
		},
		{
			name:        "interface down",
			wgBody:      `{"rows":[{"type":"interface","status":"down","name":"WG Backup","ifname":"wg1"}]}`,
			trafficBody: `{"interfaces":{}}`,
			want:        `wireguard_interface_status{interface="wg1",name="WG Backup"} 0` + "\n",
		},
		{
			name:        "no rows clears previous series",
			wgBody:      `{"rows":[]}`,
			trafficBody: `{"interfaces":{}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(newAPIServer(t, tc.wgBody, tc.trafficBody))
			if err := c.UpdateMetrics(t.Context()); err != nil {
				t.Fatalf("UpdateMetrics: %v", err)
			}
			assertExposed(t, prometheus.DefaultGatherer, tc.want)
			if got := testutil.ToFloat64(wgUpMetric); got != 1 {
				t.Errorf("wireguard_up = %v, want 1", got)
			}
			if got := testutil.ToFloat64(wgLastScrapeTimestamp); got == 0 {
				t.Error("last scrape timestamp not set")
			}
		})
	}
}

// TestUpdateMetrics_FailureKeepsSnapshot verifies wireguard_up drops to 0, the
// error counter increments, and no failure replaces any part of the snapshot.
func TestUpdateMetrics_FailureKeepsSnapshot(t *testing.T) {
	const (
		goodWG = `{"rows":[{"type":"interface","status":"up","name":"WG Server","ifname":"wg0"}]}`
		want   = `
interfaces_received_bytes_total{device="igb0",interface="lan",name="LAN"} 1000
interfaces_transmitted_bytes_total{device="igb0",interface="lan",name="LAN"} 2000
wireguard_interface_status{interface="wg0",name="WG Server"} 1
`
		otherWG      = `{"rows":[]}`
		otherTraffic = `{"interfaces":{}}`
	)
	cases := []struct {
		name        string
		wgBody      string
		trafficBody string
	}{
		{name: "first request fails", trafficBody: otherTraffic},
		{name: "first response unparsable", wgBody: "not json", trafficBody: otherTraffic},
		{name: "second request fails", wgBody: otherWG},
		{name: "second response unparsable", wgBody: otherWG, trafficBody: "not json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := newTestClient(newAPIServer(t, goodWG, trafficJSON)).UpdateMetrics(t.Context()); err != nil {
				t.Fatalf("UpdateMetrics: %v", err)
			}
			before := testutil.ToFloat64(wgScrapeErrorsMetric)

			if err := newTestClient(newAPIServer(t, tc.wgBody, tc.trafficBody)).UpdateMetrics(t.Context()); err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := testutil.ToFloat64(wgUpMetric); got != 0 {
				t.Errorf("wireguard_up = %v, want 0 after failure", got)
			}
			if after := testutil.ToFloat64(wgScrapeErrorsMetric); after != before+1 {
				t.Errorf("scrape errors = %v, want %v", after, before+1)
			}
			assertExposed(t, prometheus.DefaultGatherer, want)
		})
	}
}

// TestUpdateMetrics_NoScrapeGap scrapes while the second request is in flight:
// the previous snapshot must still be fully visible at that point.
func TestUpdateMetrics_NoScrapeGap(t *testing.T) {
	if err := newTestClient(newAPIServer(t, wgShowJSON, trafficJSON)).UpdateMetrics(t.Context()); err != nil {
		t.Fatalf("UpdateMetrics: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "traffic") {
			if n, err := testutil.GatherAndCount(prometheus.DefaultGatherer, "wireguard_peer_transfer_rx_bytes_total"); err != nil || n != 2 {
				t.Errorf("scrape during update saw %d peers, want 2 (err: %v)", n, err)
			}
			_, _ = w.Write([]byte(trafficJSON))
			return
		}
		_, _ = w.Write([]byte(`{"rows":[]}`))
	}))
	defer server.Close()

	if err := newTestClient(server).UpdateMetrics(t.Context()); err != nil {
		t.Fatalf("UpdateMetrics: %v", err)
	}
}

// snapshotGatherer exposes the snapshot of rows and interfaces on a registry
// that also fails on undescribed metrics.
func snapshotGatherer(c *Client, rows []PeerStatus, interfaces map[string]InterfaceData) prometheus.Gatherer {
	col := &snapshotCollector{}
	col.Update(c.buildSnapshot(rows, interfaces))
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(col)
	return reg
}

// TestBuildSnapshot_Peers verifies endpoint parsing, country lookup, and that
// every allowed IP produces its own series.
func TestBuildSnapshot_Peers(t *testing.T) {
	rows := []PeerStatus{
		{
			Type: "peer", Ifname: "wg0", Name: "alice", PublicKey: "PK1",
			Endpoint: "[2001:db8::1]:51820", AllowedIPs: "10.0.0.2/32,10.0.0.3/32",
			PersistentKeepalive: "25", LatestHandshakeAge: int64ptr(42),
		},
		{Type: "peer", Ifname: "wg0", Name: "bob", PublicKey: "PK2", Endpoint: "8.8.8.8:51820", AllowedIPs: "(none)"},
	}
	assertExposed(t, snapshotGatherer(&Client{geoDB: newTestGeoDB(t)}, rows, nil), `
wireguard_peer_allowed_ips{allowed_ip="10.0.0.2/32",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_allowed_ips{allowed_ip="10.0.0.3/32",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_country_code{country_code="DE",interface="wg0",peer_name="bob",public_key="PK2"} 1
wireguard_peer_country_code{country_code="unknown",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_endpoint{endpoint_ip="2001:db8::1",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_endpoint{endpoint_ip="8.8.8.8",interface="wg0",peer_name="bob",public_key="PK2"} 1
wireguard_peer_last_handshake_age_seconds{interface="wg0",peer_name="alice",public_key="PK1"} 42
wireguard_peer_latest_handshake{interface="wg0",peer_name="alice",public_key="PK1"} 0
wireguard_peer_latest_handshake{interface="wg0",peer_name="bob",public_key="PK2"} 0
wireguard_peer_persistent_keepalive_seconds{interface="wg0",peer_name="alice",public_key="PK1"} 25
wireguard_peer_persistent_keepalive_seconds{interface="wg0",peer_name="bob",public_key="PK2"} 0
wireguard_peer_transfer_rx_bytes_total{interface="wg0",peer_name="alice",public_key="PK1"} 0
wireguard_peer_transfer_rx_bytes_total{interface="wg0",peer_name="bob",public_key="PK2"} 0
wireguard_peer_transfer_tx_bytes_total{interface="wg0",peer_name="alice",public_key="PK1"} 0
wireguard_peer_transfer_tx_bytes_total{interface="wg0",peer_name="bob",public_key="PK2"} 0
`)
}

// TestBuildSnapshot_Duplicates verifies repeated rows and allowed-ips keep the
// first value instead of failing the whole Gather.
func TestBuildSnapshot_Duplicates(t *testing.T) {
	peer := PeerStatus{Type: "peer", Ifname: "wg0", Name: "alice", PublicKey: "PK1", AllowedIPs: "10.0.0.2/32,10.0.0.2/32", TransferRx: 1}
	repeated := peer
	repeated.TransferRx = 2
	iface := PeerStatus{Type: "interface", Ifname: "wg0", Name: "WG Server", Status: "up"}

	assertExposed(t, snapshotGatherer(&Client{}, []PeerStatus{peer, repeated, iface, iface}, nil), `
wireguard_interface_status{interface="wg0",name="WG Server"} 1
wireguard_peer_allowed_ips{allowed_ip="10.0.0.2/32",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_country_code{country_code="unknown",interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_latest_handshake{interface="wg0",peer_name="alice",public_key="PK1"} 0
wireguard_peer_persistent_keepalive_seconds{interface="wg0",peer_name="alice",public_key="PK1"} 0
wireguard_peer_transfer_rx_bytes_total{interface="wg0",peer_name="alice",public_key="PK1"} 1
wireguard_peer_transfer_tx_bytes_total{interface="wg0",peer_name="alice",public_key="PK1"} 0
`)
}

// TestBuildSnapshot_UnparsableBytes verifies an unparsable number drops only that
// series, not the other direction or the rest of the scrape.
func TestBuildSnapshot_UnparsableBytes(t *testing.T) {
	interfaces := map[string]InterfaceData{
		"lan": {Device: "igb0", Name: "LAN", BytesReceived: "not-a-number", BytesTransmitted: "2000"},
		"wan": {Device: "igb1", Name: "WAN", BytesReceived: "1000", BytesTransmitted: ""},
	}
	assertExposed(t, snapshotGatherer(&Client{}, nil, interfaces), `
interfaces_received_bytes_total{device="igb1",interface="wan",name="WAN"} 1000
interfaces_transmitted_bytes_total{device="igb0",interface="lan",name="LAN"} 2000
`)
}
