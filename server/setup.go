package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net"
	"os"
)

func parseArgs(s *state) (port string) {
	if len(os.Args) < 2 {
		Fatalln("Usage:", os.Args[0], "PORT [PRIVATE_KEY]")
	}

	port = os.Args[1]
	if len(os.Args) > 2 {
		priv, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil || len(priv) != 32 {
			Eprintln(os.Stderr, "Error parsing public key")
		}
		copy(s.privKey[:], priv)
	} else {
		_, err := rand.Read(s.privKey[:])
		if err != nil {
			Fatalln("Fatal error reading random data:", err)
		}
		s.privKey.clamp()
	}
	return
}

func (s *state) init(port string) {
	s.keyMap = make(PeerMap)
	s.indexMap = make(IndexMap)

	// the client can only handle IPv4 addresses right now.
	listenAddr, err := net.ResolveUDPAddr("udp4", ":"+port)
	if err != nil {
		log.Panicln("Error getting UDP address", err)
	}

	s.conn, err = net.ListenUDP("udp4", listenAddr)
	if err != nil {
		log.Panicln("Error getting UDP listen connection")
	}

}
