package network

import (
	"net"
	"time"
)

// Server stores data relating to the server
type Server struct {
	Hostname string
	Addr     *net.IPAddr
	Port     uint16
	Pubkey   Key

	LastHandshake time.Time
}

// NewServer creates a new Server struct from the specified hostname, port, and
// public key
func NewServer(hostname string, port uint16, pubkey Key) (Server, error) {
	serverAddr, err := HostToAddr(hostname)
	if err != nil {
		return Server{}, err
	}

	return Server{
		Hostname: hostname,
		Addr:     serverAddr,
		Port:     port,
		Pubkey:   pubkey,
	}, nil
}
