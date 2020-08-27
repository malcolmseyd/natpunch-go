package cmd

import (
	"encoding/base64"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/malcolmseyd/natpunch-go/client/network"
)

const persistentKeepalive = "25"

// RunCmd runs a command and returns the output, returning any errors
func RunCmd(command string, args ...string) (string, error) {
	outBytes, err := exec.Command(command, args...).Output()
	if err != nil {
		return "", err
	}
	return string(outBytes), nil
}

// GetClientPort gets the client's listening port for Wireguard
func GetClientPort(iface string) uint16 {
	output, err := RunCmd("wg", "show", iface, "listen-port")
	if err != nil {
		log.Fatalln("Error getting listen port:", err)
	}
	// guaranteed castable to uint16, as ports are only 2 bytes and positive
	port, err := strconv.ParseUint(strings.TrimSpace(output), 10, 16)
	if err != nil {
		log.Fatalln("Error parsing listen port:", err)
	}
	return uint16(port)
}

// GetPeers returns a list of peers on the Wireguard interface
func GetPeers(iface string) []string {
	output, err := RunCmd("wg", "show", iface, "peers")
	if err != nil {
		log.Fatalln("Error getting peers:", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n")
}

// GetClientPubkey returns the publib key on the Wireguard interface
func GetClientPubkey(iface string) network.Key {
	var keyArr [32]byte
	output, err := RunCmd("wg", "show", iface, "public-key")
	if err != nil {
		log.Fatalln("Error getting client pubkey:", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing client pubkey:", err)
	}
	copy(keyArr[:], keyBytes)
	return network.Key(keyArr)
}

// GetClientPrivkey returns the private key on the Wireguard interface
func GetClientPrivkey(iface string) network.Key {
	var keyArr [32]byte
	output, err := RunCmd("wg", "show", iface, "private-key")
	if err != nil {
		log.Fatalln("Error getting client privkey:", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing client privkey:", err)
	}
	copy(keyArr[:], keyBytes)
	return network.Key(keyArr)
}

// SetPeer updates a peer's endpoint and keepalive with `wg`. keepalive is in seconds
func SetPeer(peer *network.Peer, keepalive int, iface string) {
	keyString := base64.StdEncoding.EncodeToString(peer.Pubkey[:])
	RunCmd("wg",
		"set", iface,
		"peer", keyString,
		"persistent-keepalive", strconv.Itoa(keepalive),
		"endpoint", peer.IP.String()+":"+strconv.FormatUint(uint64(peer.Port), 10),
	)
}
