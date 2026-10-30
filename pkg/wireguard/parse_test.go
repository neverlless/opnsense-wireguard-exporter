package wireguard

import (
	"reflect"
	"testing"
)

func TestParseEndpointHost(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4", "1.2.3.4:51820", "1.2.3.4"},
		{"ipv6 bracketed", "[2001:db8::1]:51820", "2001:db8::1"},
		{"ipv6 loopback", "[::1]:51820", "::1"},
		{"none", "(none)", ""},
		{"empty", "", ""},
		{"host only no port", "1.2.3.4", "1.2.3.4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := endpointHost(c.in); got != c.want {
				t.Errorf("endpointHost(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParseSplitAllowedIPs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"multiple", "10.0.0.2/32,10.0.0.3/32", []string{"10.0.0.2/32", "10.0.0.3/32"}},
		{"single", "10.0.0.2/32", []string{"10.0.0.2/32"}},
		{"subnet", "10.0.0.0/24", []string{"10.0.0.0/24"}},
		{"default route", "0.0.0.0/0", []string{"0.0.0.0/0"}},
		{"ipv6", "fd00::2/128,10.0.0.2/32", []string{"fd00::2/128", "10.0.0.2/32"}},
		{"spaces", "10.0.0.2/32, 10.0.0.3/32", []string{"10.0.0.2/32", "10.0.0.3/32"}},
		{"none", "(none)", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := splitAllowedIPs(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitAllowedIPs(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestParseKeepalive(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"off", 0},
		{"", 0},
		{"25", 25},
		{"120", 120},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := parseKeepalive(c.in); got != c.want {
				t.Errorf("parseKeepalive(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
