package wireguard

import (
	"net"
	"strconv"
	"strings"
)

// endpointHost extracts the bare host (IPv4 or IPv6, without brackets) from a
// WireGuard endpoint string as produced by `wg show dump`. Endpoints look like
// "1.2.3.4:51820" or "[2001:db8::1]:51820". Peers that have never connected are
// reported as "(none)". Returns "" for empty or "(none)" endpoints.
func endpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || endpoint == "(none)" {
		return ""
	}

	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]")
	}

	// No port present (or malformed) — strip any brackets and return as-is.
	return strings.Trim(endpoint, "[]")
}

// splitAllowedIPs turns a comma-separated allowed-ips list ("10.0.0.2/32,10.0.0.3/32")
// into its entries, keeping the CIDR mask because 10.0.0.0/24 and 10.0.0.0/32
// are different allowed IPs. Returns nil for empty or "(none)" values.
func splitAllowedIPs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "(none)" {
		return nil
	}

	var ips []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "(none)" {
			continue
		}
		ips = append(ips, part)
	}
	return ips
}

// parseKeepalive converts the persistent-keepalive field ("off" or a number of
// seconds) into a float64. "off" and empty values map to 0.
func parseKeepalive(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "off" {
		return 0
	}
	if v, err := strconv.ParseFloat(raw, 64); err == nil {
		return v
	}
	return 0
}
