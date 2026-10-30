package main

import (
	"testing"
	"time"

	"opnsense-wireguard-exporter/pkg/wireguard"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("OPNSENSE_BASE_URL", "https://fw.example")
	t.Setenv("OPNSENSE_API_KEY", "key")
	t.Setenv("OPNSENSE_API_SECRET", "secret")

	got := configFromEnv()
	want := wireguard.Config{
		BaseURL:       "https://fw.example",
		APIKey:        "key",
		APISecret:     "secret",
		GeoLiteDBPath: defaultGeoLiteDBPath,
		TLSInsecure:   true,
	}
	if got != want {
		t.Errorf("configFromEnv() = %+v, want %+v", got, want)
	}

	t.Setenv("OPNSENSE_TLS_INSECURE", "false")
	t.Setenv("GEOLITE_DB_PATH", "/tmp/geo.mmdb")
	t.Setenv("OPNSENSE_CA_FILE", "/tmp/ca.pem")
	got = configFromEnv()
	if got.TLSInsecure || got.GeoLiteDBPath != "/tmp/geo.mmdb" || got.CAFile != "/tmp/ca.pem" {
		t.Errorf("configFromEnv() ignored overrides: %+v", got)
	}
}

func TestParseUpdateInterval(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", in: "30", want: 30 * time.Second},
		{name: "one", in: "1", want: time.Second},
		{name: "zero", in: "0", wantErr: true},
		{name: "negative", in: "-5", wantErr: true},
		{name: "not a number", in: "soon", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "overflows duration", in: "9223372037", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUpdateInterval(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseUpdateInterval(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("parseUpdateInterval(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
