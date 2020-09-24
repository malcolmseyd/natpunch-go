package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	//udpProtocol = 17
	// EmptyUDPSize is the size of an empty UDP packet
	EmptyUDPSize = 28

	timeout = time.Second * 10

	// PacketHandshakeInit identifies handshake initiation packets
	PacketHandshakeInit byte = 1
	// PacketHandshakeResp identifies handshake response packets
	PacketHandshakeResp byte = 2
	// PacketData identifies regular data packets
	PacketData byte = 3
)

var (
	// ErrPacketType is returned when an unexpected packet type is encountered
	ErrPacketType = errors.New("client/network: incorrect packet type")
	// ErrNonce is returned when the nonce on a packet isn't valid
	ErrNonce = errors.New("client/network: invalid nonce")
	// ErrNoIP is returned when no appropriate ip address could be found
	ErrNoIP = errors.New("client/network: no valid ip address found")

	// RekeyDuration is the time after which keys are invalid and a new handshake is required.
	RekeyDuration = 5 * time.Minute
)

// EmptyUDPSize is the size of the IPv4 and UDP headers combined.

// Key stores a 32 byte representation of a Wireguard key
type Key [32]byte

// Peer stores data about a peer's key and endpoint
// While Resolved == false, we consider IP and Port to be uninitialized
type Peer struct {
	Resolved bool
	IP       net.IP
	Port     uint16
	Pubkey   Key
}

// GetClientIP gets source ip address that will be used when sending data to dstIP
func GetClientIP(dstIP net.IP) net.IP {
	// TODO experiment with Layer 4 sockets so we can drop this library
	// i wanted to use gopacket/routing but it breaks when the vpn iface is already up
	routes, err := netlink.RouteGet(dstIP)
	if err != nil {
		log.Fatalln("Error getting route:", err)
	}
	// pick the first one cuz why not
	return routes[0].Src
}

// HostToAddr resolves a hostname, whether DNS or IP to a valid net.IPAddr
func HostToAddr(hostStr string) (*net.IPAddr, error) {
	remoteAddrs, err := net.LookupHost(hostStr)
	if err != nil {
		return nil, err
	}

	for _, addrStr := range remoteAddrs {
		if remoteAddr, err := net.ResolveIPAddr("ip4", addrStr); err == nil {
			return remoteAddr, nil
		}
	}
	return nil, ErrNoIP
}

// ParseEndpoint takes a response packet and parses it into an IP and port.
// There's no error checking, we assume that data passed in is valid
func ParseEndpoint(response []byte) (ip net.IP, port uint16) {
	buf := bytes.NewBuffer(response)
	binary.Read(buf, binary.BigEndian, &ip)
	port = binary.BigEndian.Uint16(response[4:6])
	return ip, port
}
