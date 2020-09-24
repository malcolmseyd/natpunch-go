package util

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/malcolmseyd/natpunch-go/client/network"
)

var (
	ErrKeyBase64 = errors.New("client/util: error decoding key from base64 string")
)

// MakePeerSlice constructs a slice of Peers, each with a Pubkey
func MakePeerSlice(peerKeys []string) ([]network.Peer, error) {
	keys := make([]network.Peer, len(peerKeys))
	for i, key := range peerKeys {
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, ErrKeyBase64
		}

		keyArr := [32]byte{}
		copy(keyArr[:], keyBytes)

		peer := network.Peer{
			Pubkey:   network.Key(keyArr),
			Resolved: false,
		}
		keys[i] = peer
	}
	return keys, nil
}

// Eprintln is fmt.Println to stderr
func Eprintln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
}

// Eprint is fmt.Print to stderr
func Eprint(args ...interface{}) {
	fmt.Fprint(os.Stderr, args...)
}

// Eprintf is fmt.Print to stderr
func Eprintf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}
