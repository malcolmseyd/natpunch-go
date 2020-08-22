package crypto

import (
	"bytes"
	"encoding/binary"
	"time"
)

// ConstructHandshakeReq creates a handshake request packet from a session
func (s *Session) ConstructHandshakeReq() ([]byte, error) {
	var err error
	packet := make([]byte, 0, handshakeReqSize)

	sendIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(sendIndex, s.sendIndex)
	packet = append(packet, sendIndex...)

	s.created = uint64(time.Now().UnixNano())
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, s.created)

	binary.BigEndian.PutUint32(packet, s.sendIndex)
	packet = append(packet, s.ephemPub...)

	// seal staticPub
	secret, err := ecdh(s.ephemPriv, s.theirStaticPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(secret, sendIndex, 32)
	if err != nil {
		return nil, err
	}
	packet, err = aeadSeal(packet, key, 0, s.staticPub, nil)
	if err != nil {
		return nil, err
	}

	// seal timestamp
	secret, err = ecdh(s.staticPriv, s.theirStaticPub)
	if err != nil {
		return nil, err
	}
	key, err = deriveKey(secret, sendIndex, 32)
	if err != nil {
		return nil, err
	}
	packet, err = aeadSeal(packet, key, 0, timestamp, nil)
	if err != nil {
		return nil, err
	}

	// calculate MAC with staticPub
	tmp, err := hash(append(labelMac, s.staticPub...))
	if err != nil {
		return nil, err
	}
	macBytes, err := mac(tmp, packet)
	if err != nil {
		return nil, err
	}
	packet = append(packet, macBytes...)

	return packet, nil
}

// ParseHandshakeReq parses a handshake request packet into an existing session
func (s *Session) ParseHandshakeReq(packet []byte) error {
	if len(packet) != handshakeReqSize {
		return ErrPacket
	}

	var err error
	curr := packet

	// open staticPub
	recvIndexBytes := curr[:4]
	curr = curr[4:]
	recvIndex := binary.BigEndian.Uint32(recvIndexBytes)

	theirEphemPub := curr[:32]
	curr = curr[32:]

	secret, err := ecdh(s.staticPriv, theirEphemPub)
	if err != nil {
		return err
	}
	key, err := deriveKey(secret, recvIndexBytes, 32)
	if err != nil {
		return err
	}
	theirStaticPub, err := aeadOpen(nil, key, 0, curr[:32+emptyAeadSize], nil)
	if err != nil {
		return err
	}
	curr = curr[32+emptyAeadSize:]

	// verify MAC with staticPub
	tmp, err := hash(append(labelMac, s.theirStaticPub...))
	if err != nil {
		return err
	}
	macOffset := len(packet) - macSize
	macBytes, err := mac(tmp, packet[:macOffset])
	if err != nil {
		return err
	}
	if !bytes.Equal(macBytes, packet[macOffset:]) {
		return ErrDecrypt
	}

	// open timestamp
	secret, err = ecdh(s.staticPriv, s.theirStaticPub)
	if err != nil {
		return err
	}
	key, err = deriveKey(secret, recvIndexBytes, 32)
	if err != nil {
		return err
	}
	timestamp, err := aeadOpen(nil, key, 0, curr[:8+emptyAeadSize], nil)
	if err != nil {
		return err
	}

	// identity fully verified, we can record values now
	s.recvIndex = recvIndex
	s.theirEphemPub = theirEphemPub
	s.theirStaticPub = theirStaticPub
	s.created = binary.BigEndian.Uint64(timestamp)

	return nil
}
