package wireguard

type WireGuardStatus struct {
	Rows []PeerStatus `json:"rows"`
}

type PeerStatus struct {
	Type                string `json:"type"`
	PublicKey           string `json:"public-key"`
	Endpoint            string `json:"endpoint"`
	AllowedIPs          string `json:"allowed-ips"`
	LatestHandshake     int64  `json:"latest-handshake"`
	LatestHandshakeAge  *int64 `json:"latest-handshake-age"`
	TransferRx          int64  `json:"transfer-rx"`
	TransferTx          int64  `json:"transfer-tx"`
	PersistentKeepalive string `json:"persistent-keepalive"`
	Status              string `json:"status"`
	Name                string `json:"name"`
	Ifname              string `json:"ifname"`
}

type InterfaceTrafficStatus struct {
	Interfaces map[string]InterfaceData `json:"interfaces"`
}

type InterfaceData struct {
	Device           string `json:"device"`
	BytesReceived    string `json:"bytes received"`
	BytesTransmitted string `json:"bytes transmitted"`
	Name             string `json:"name"`
}
