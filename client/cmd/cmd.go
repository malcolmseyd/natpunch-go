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

func RunCmd(command string, args ...string) (string, error) {
	outBytes, err := exec.Command(command, args...).Output()
	if err != nil {
		return "", err
	}
	return string(outBytes), nil
}

func GetClientPort(iface string) uint16 {
	output, err := RunCmd("wg", "show", iface, "listen-port")
	if err != nil {
		log.Fatalln("Error getting listen port:", err)
	}
	// guaranteed castable to uint16
	port, err := strconv.ParseUint(strings.TrimSpace(output), 10, 16)
	if err != nil {
		log.Fatalln("Error parsing listen port:", err)
	}
	return uint16(port)
}

func GetPeers(iface string) []string {
	output, err := RunCmd("wg", "show", iface, "peers")
	if err != nil {
		log.Fatalln("Error getting peers", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n")
}

func GetClientPubkey(iface string) network.Pubkey {
	var keyArr [32]byte
	output, err := RunCmd("wg", "show", iface, "public-key")
	if err != nil {
		log.Fatalln("Error getting client pubkey:", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing client pubkey")
	}
	copy(keyArr[:], keyBytes)
	return network.Pubkey(keyArr)
}

func SetPeer(peer *network.Peer, keepalive, iface string) {
	keyString := base64.StdEncoding.EncodeToString(peer.Pubkey[:])
	RunCmd("wg",
		"set", iface,
		"peer", keyString,
		"persistent-keepalive", keepalive,
		"endpoint", peer.IP.String()+":"+strconv.FormatUint(uint64(peer.Port), 10),
	)
}
