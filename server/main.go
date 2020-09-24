package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/flynn/noise"
	"github.com/malcolmseyd/natpunch-go/server/auth"
	"golang.org/x/crypto/curve25519"
)

const (
	// PacketHandshakeInit identifies handshake initiation packets
	PacketHandshakeInit byte = 1
	// PacketHandshakeResp identifies handshake response packets
	PacketHandshakeResp byte = 2
	// PacketData identifies regular data packets.
	PacketData byte = 3
)

var (
	// ErrPacketType is returned when an unexpected packet type is encountered
	ErrPacketType = errors.New("server: incorrect packet type")
	// ErrPeerNotFound is returned when the requested peer is not found
	ErrPeerNotFound = errors.New("server: peer not found")
	// ErrPubkey is returned when the public key recieved does not match the one we expect
	ErrPubkey = errors.New("server: public key did not match expected one")
	// ErrOldTimestamp is returned when a handshake timestamp isn't newer than the previous one
	ErrOldTimestamp = errors.New("server: handshake timestamp isn't new")
	// ErrNoTimestamp is returned when the handshake packet doesn't contain a timestamp
	ErrNoTimestamp = errors.New("server: handshake had no timestamp")
	// ErrNonce is returned when the nonce on a packet isn't valid
	ErrNonce = errors.New("client/network: invalid nonce")

	timeout = 5 * time.Second

	noiseConfig = noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Random:      rand.Reader,
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		Prologue:    []byte("natpunch-go is the best :)"),
	}
)

// Key stores a Wireguard key
type Key [32]byte

// we use pointers on these maps so that two maps can link to one object

// PeerMap stores the peers by key
type PeerMap map[Key]*Peer

// IndexMap stores the Peers by index
type IndexMap map[uint32]*Peer

// Peer represents a Wireguard peer.
type Peer struct {
	ip     net.IP
	port   uint16
	pubkey Key

	index      uint32
	send, recv *auth.CipherState
	// UnixNano cast to uint64
	lastHandshake uint64
}

type state struct {
	conn     *net.UDPConn
	keyMap   PeerMap
	indexMap IndexMap
	privKey  Key
}

func main() {
	s := state{}

	port := parseArgs(&s)
	s.init(port)

	pubkey, _ := curve25519.X25519(s.privKey[:], curve25519.Basepoint)
	fmt.Println("Starting nat-punching server on port", port)
	fmt.Println("Public key:", base64.StdEncoding.EncodeToString(pubkey))

	for {
		err := s.handleConnection()
		if err != nil {
			fmt.Println("Error handling the connection", err)
		}
	}
}

func (s *state) handleConnection() error {
	packet := make([]byte, 4096)

	n, clientAddr, err := s.conn.ReadFromUDP(packet)
	if err != nil {
		return err
	}
	packet = packet[:n]

	packetType := packet[0]
	packet = packet[1:]

	if packetType == PacketHandshakeInit {
		return s.handshake(packet, clientAddr, timeout)
	} else if packetType == PacketData {
		return s.dataPacket(packet, clientAddr, timeout)
	} else {
		fmt.Println("Unknown packet type:", packetType)
		fmt.Println(hex.Dump(packet))
	}

	return nil
}

// some curve25519 magic, make sure the key is secure
func (k *Key) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}
