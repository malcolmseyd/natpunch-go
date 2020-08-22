package crypto

import (
	"bytes"
	"encoding/binary"
)

// ConstructHandshakeResp constructs a handshake response packet from the session
func (s *Session) ConstructHandshakeResp() ([]byte, error) {
	var err error
	packet := make([]byte, 0, handshakeRespSize)

	s.ephemPriv, err = genPrivkey()
	if err != nil {
		return nil, err
	}
	s.ephemPub, err = genPubkey(s.ephemPriv)
	if err != nil {
		return nil, err
	}

	sendIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(sendIndex, s.sendIndex)
	packet = append(packet, sendIndex...)

	packet = append(packet, s.ephemPub...)

	// ephem-ephem secret
	secret, err := ecdh(s.ephemPriv, s.theirEphemPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(secret, sendIndex, 32)
	if err != nil {
		return nil, err
	}
	// static-static secret
	secret, err = ecdh(s.staticPriv, s.theirStaticPub)
	if err != nil {
		return nil, err
	}
	key, err = deriveKey(secret, key, 32)
	if err != nil {
		return nil, err
	}
	packet, err = aeadSeal(packet, key, s.sendCounter, nil, nil)
	if err != nil {
		return nil, err
	}

	tmp, err := hash(append(labelMac, s.theirStaticPub...))
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

// ParseHandshakeResp parses a handshake response packet into an existing session
func (s *Session) ParseHandshakeResp(packet []byte) error {
	if len(packet) != handshakeRespSize {
		return ErrPacket
	}

	var err error
	curr := packet

	recvIndex := curr[:4]
	curr = curr[4:]
	s.recvIndex = binary.BigEndian.Uint32(recvIndex)

	s.theirEphemPub = curr[:32]
	curr = curr[32:]

	tmp, err := hash(append(labelMac, s.staticPub...))
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

	// open empty AEAD
	// ephem-ephem secret
	secret, err := ecdh(s.ephemPriv, s.theirEphemPub)
	if err != nil {
		return err
	}
	key, err := deriveKey(secret, recvIndex, 32)
	if err != nil {
		return err
	}
	// static-static secret
	secret, err = ecdh(s.staticPriv, s.theirStaticPub)
	if err != nil {
		return err
	}
	key, err = deriveKey(secret, key, 32)
	if err != nil {
		return err
	}
	_, err = aeadOpen(nil, key, 0, curr[:emptyAeadSize], nil)
	if err != nil {
		return err
	}

	return nil
}
