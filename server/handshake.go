package main

import (
	"encoding/binary"
	"github.com/flynn/noise"
	"github.com/malcolmseyd/natpunch-go/server/auth"
	"golang.org/x/crypto/curve25519"
	"net"
	"time"
)

// TODO timeout properly
func (s *state) handshake(packet []byte, clientAddr *net.UDPAddr, timeout time.Duration) (err error) {
	config := noiseConfig
	config.StaticKeypair = noise.DHKey{
		Private: s.privKey[:],
	}
	config.StaticKeypair.Public, err = curve25519.X25519(config.StaticKeypair.Private, curve25519.Basepoint)
	if err != nil {
		return
	}

	handshake, err := noise.NewHandshakeState(config)
	if err != nil {
		return
	}

	indexBytes := packet[:4]
	index := binary.BigEndian.Uint32(indexBytes)
	packet = packet[4:]

	// read init packet from client
	timestampBytes, _, _, err := handshake.ReadMessage(nil, packet)
	if err != nil {
		return
	}
	if len(timestampBytes) == 0 {
		err = ErrNoTimestamp
	}
	timestamp := binary.BigEndian.Uint64(timestampBytes)

	var pubkey Key
	copy(pubkey[:], handshake.PeerStatic())
	client, ok := s.keyMap[pubkey]
	if !ok {
		client = &Peer{
			pubkey: pubkey,
		}
		s.keyMap[pubkey] = client
	}
	if timestamp <= client.lastHandshake {
		err = ErrOldTimestamp
		return
	}
	client.lastHandshake = timestamp
	// clear old entry
	s.indexMap[index] = nil
	client.ip = clientAddr.IP
	client.port = uint16(clientAddr.Port)
	// if index is already taken, set a new one
	for {
		_, ok = s.indexMap[index]
		if !ok {
			break
		}
		index++
	}
	client.index = index
	binary.BigEndian.PutUint32(indexBytes, index)
	s.indexMap[index] = client

	// send response to client
	header := append([]byte{PacketHandshakeResp}, indexBytes...)
	// recv and send are opposite order from client code
	packet, recv, send, err := handshake.WriteMessage(header, nil)
	if err != nil {
		return
	}
	client.send = auth.NewCipherState(send.Cipher())
	client.recv = auth.NewCipherState(recv.Cipher())

	_, err = s.conn.WriteTo(packet, clientAddr)

	return
}
