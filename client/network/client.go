package network

import (
	"net"
)

// Client stores info relating to the local Wireguard device
type Client struct {
	IP      net.IP
	Port    uint16
	Pubkey  Key
	Privkey Key
}
