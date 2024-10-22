package wireguard

type WireGuardStatus struct {
	Total    int          `json:"total"`
	RowCount int          `json:"rowCount"`
	Current  int          `json:"current"`
	Rows     []PeerStatus `json:"rows"`
}

type PeerStatus struct {
	If              string `json:"if"`
	Type            string `json:"type"`
	PublicKey       string `json:"public-key"`
	Endpoint        string `json:"endpoint"`
	AllowedIPs      string `json:"allowed-ips"`
	LatestHandshake int64  `json:"latest-handshake"`
	TransferRx      int64  `json:"transfer-rx"`
	TransferTx      int64  `json:"transfer-tx"`
	Name            string `json:"name"`
	Ifname          string `json:"ifname"`
}
