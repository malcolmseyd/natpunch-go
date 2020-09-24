package network

import (
	"encoding/base64"
	"errors"
	"github.com/malcolmseyd/natpunch-go/client/util"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

var (
	// ErrIfaceDown is returned when the Wireguard interface is down
	ErrIfaceDown = errors.New("client/net: Wireguard interface down")
)

// RunCmd runs a command and returns the output, returning any errors
func RunCmd(command string, args ...string) (string, error) {
	outBytes, err := exec.Command(command, args...).Output()
	if err != nil {
		return "", err
	}
	return string(outBytes), nil
}

func SetIfaceUp(ifaceName string) (err error) {
	_, err = RunCmd("wg-quick", "up", ifaceName)
	return
}

// NewClient creates a new network.Client object for the Wireguard interface specified
func NewClient(ifaceName string, server *Server) (client Client, err error) {
	// get the source ip that we'll send the packet from
	client.IP = GetClientIP(server.Addr.IP)

	// get info about the Wireguard config
	client.Port = GetClientPort(ifaceName)
	client.Pubkey = GetClientPubkey(ifaceName)
	client.Privkey = GetClientPrivkey(ifaceName)

	return
}

// GetClientPort gets the client's listening port for Wireguard
func GetClientPort(iface string) uint16 {
	output, err := RunCmd("wg", "show", iface, "listen-port")
	if err != nil {
		log.Fatalln("Error getting listen port:", err)
	}
	// guaranteed to cast into uint16, as ports are only 2 bytes and positive
	port, err := strconv.ParseUint(strings.TrimSpace(output), 10, 16)
	if err != nil {
		log.Fatalln("Error parsing listen port:", err)
	}
	return uint16(port)
}

// GetPeers returns a list of peers on the Wireguard interface
func GetPeers(iface string) ([]Peer, error) {
	output, err := RunCmd("wg", "show", iface, "peers")
	if err != nil {
		return nil, err
	}
	peerKeysStr := strings.Split(strings.TrimSpace(output), "\n")
	return util.MakePeerSlice(peerKeysStr)
}

// GetClientPubkey returns the public key on the Wireguard interface
func GetClientPubkey(iface string) (key Key) {
	output, err := RunCmd("wg", "show", iface, "public-key")
	if err != nil {
		log.Fatalln("Error getting client pubkey:", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing client pubkey:", err)
	}
	copy(key[:], keyBytes)
	return
}

// GetClientPrivkey returns the public key on the Wireguard interface
func GetClientPrivkey(iface string) (key Key) {
	output, err := RunCmd("wg", "show", iface, "private-key")
	if err != nil {
		log.Fatalln("Error getting client pubkey:", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing client privkey:", err)
	}
	copy(key[:], keyBytes)
	return
}

// SetPeer updates a peer's endpoint and keepalive with `wg`. keepalive is in seconds
func UpdatePeer(peer *Peer, keepalive int, iface string) (err error) {
	keyString := base64.StdEncoding.EncodeToString(peer.Pubkey[:])
	_, err = RunCmd("wg",
		"set", iface,
		"peer", keyString,
		"persistent-keepalive", strconv.Itoa(keepalive),
		"endpoint", peer.IP.String()+":"+strconv.FormatUint(uint64(peer.Port), 10),
	)
	return
}
