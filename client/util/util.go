package util

import (
	"encoding/base64"
	"log"

	"github.com/malcolmseyd/natpunch-go/client/network"
)

// MakePeerSlice constructs a slice of Peers, each with a Pubkey
func MakePeerSlice(peerKeys []string) []network.Peer {
	keys := make([]network.Peer, len(peerKeys))
	for i, key := range peerKeys {
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Fatalln("Error decoding key "+key+":", err)
		}

		keyArr := [32]byte{}
		copy(keyArr[:], keyBytes)

		peer := network.Peer{
			Pubkey:   network.Key(keyArr),
			Resolved: false,
		}
		keys[i] = peer
	}
	return keys
}
