package wireguard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestClient creates a Client wired to the given test server, without requiring
// a GeoLite2 database on disk.
func newTestClient(server *httptest.Server) *Client {
	return &Client{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		APISecret:  "test-secret",
		HTTPClient: server.Client(),
		cache:      make(map[string]string),
	}
}

func TestNewClient_Validation(t *testing.T) {
	valid := Config{BaseURL: "https://fw.example", APIKey: "k", APISecret: "s"}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{name: "valid https", mutate: func(*Config) {}},
		{name: "valid http with port", mutate: func(c *Config) { c.BaseURL = "http://10.0.0.1:8443" }},
		{name: "missing key", mutate: func(c *Config) { c.APIKey = "" }, wantErr: true},
		{name: "missing secret", mutate: func(c *Config) { c.APISecret = "" }, wantErr: true},
		{name: "missing url", mutate: func(c *Config) { c.BaseURL = "" }, wantErr: true},
		{name: "wrong scheme", mutate: func(c *Config) { c.BaseURL = "ftp://fw.example" }, wantErr: true},
		{name: "no scheme", mutate: func(c *Config) { c.BaseURL = "fw.example" }, wantErr: true},
		{name: "no host", mutate: func(c *Config) { c.BaseURL = "https://" }, wantErr: true},
		{name: "port only", mutate: func(c *Config) { c.BaseURL = "https://:443" }, wantErr: true},
		{name: "unparsable", mutate: func(c *Config) { c.BaseURL = "https://fw.example:port" }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			client, err := NewClient(cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewClient error = %v, wantErr %v", err, tc.wantErr)
			}
			if client != nil {
				_ = client.Close()
			}
		})
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	client, err := NewClient(Config{BaseURL: "https://fw.example//", APIKey: "k", APISecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if client.BaseURL != "https://fw.example" {
		t.Errorf("BaseURL = %q", client.BaseURL)
	}
}

// writeCertPEM stores der as a PEM file and returns its path.
func writeCertPEM(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// otherCADER returns a self-signed certificate unrelated to the httptest server.
func otherCADER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "other CA"},
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestNewClient_TLS verifies against a real TLS server that the CA file wins
// over TLSInsecure, in both directions.
func TestNewClient_TLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	cases := []struct {
		name     string
		insecure bool
		caFile   string
		wantErr  bool
	}{
		{name: "insecure skips verification", insecure: true},
		{name: "secure without CA rejects server", wantErr: true},
		{name: "server CA is trusted", caFile: writeCertPEM(t, server.Certificate().Raw)},
		{name: "CA file enables verification despite insecure", insecure: true, caFile: writeCertPEM(t, otherCADER(t)), wantErr: true},
		{name: "server CA with insecure", insecure: true, caFile: writeCertPEM(t, server.Certificate().Raw)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(Config{BaseURL: server.URL, APIKey: "k", APISecret: "s", TLSInsecure: tc.insecure, CAFile: tc.caFile})
			if err != nil {
				t.Fatal(err)
			}
			defer client.HTTPClient.CloseIdleConnections()
			if _, err := client.fetch("/"); (err != nil) != tc.wantErr {
				t.Errorf("fetch error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewClient_BadCAFile(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{invalid, filepath.Join(t.TempDir(), "missing.pem")} {
		if _, err := NewClient(Config{BaseURL: "https://fw.example", APIKey: "k", APISecret: "s", TLSInsecure: true, CAFile: path}); err == nil {
			t.Errorf("NewClient with CA file %s: expected error", path)
		}
	}
}

// TestFetch_HTMLResponse verifies that fetch returns a descriptive error when the
// server returns an HTML body (e.g. a login page) instead of JSON.
func TestFetch_HTMLResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>Login</body></html>`))
	}))
	defer server.Close()

	client := newTestClient(server)
	_, err := client.fetch("/api/wireguard/service/show")
	if err == nil {
		t.Fatal("expected an error for HTML response, got nil")
	}
	if !strings.Contains(err.Error(), "HTML instead of JSON") {
		t.Errorf("expected error to mention 'HTML instead of JSON', got: %v", err)
	}
}

// TestFetch_HTMLResponseWithLeadingWhitespace verifies that HTML responses with
// leading whitespace are also correctly detected.
func TestFetch_HTMLResponseWithLeadingWhitespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("\n  <!DOCTYPE html><html><body>Login</body></html>"))
	}))
	defer server.Close()

	client := newTestClient(server)
	_, err := client.fetch("/api/wireguard/service/show")
	if err == nil {
		t.Fatal("expected an error for HTML response with leading whitespace, got nil")
	}
	if !strings.Contains(err.Error(), "HTML instead of JSON") {
		t.Errorf("expected error to mention 'HTML instead of JSON', got: %v", err)
	}
}

// TestFetch_NonOKStatus verifies that fetch returns an error for non-200 HTTP statuses.
func TestFetch_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := newTestClient(server)
	_, err := client.fetch("/api/wireguard/service/show")
	if err == nil {
		t.Fatal("expected an error for non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status code") {
		t.Errorf("expected error to mention 'unexpected status code', got: %v", err)
	}
}

// TestFetch_ValidJSON verifies that fetch succeeds when the server returns valid JSON.
func TestFetch_ValidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	}))
	defer server.Close()

	client := newTestClient(server)
	body, err := client.fetch("/api/wireguard/service/show")
	if err != nil {
		t.Fatalf("expected no error for valid JSON response, got: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty body")
	}
}
