package crypto

import (
	"encoding/binary"
)

// EncryptPacket encrypts the data passed in and returns it in a []byte
func (s *Session) EncryptPacket(plaintext []byte) ([]byte, error) {
	if s.sendKey == nil {
		s.deriveDataKeys()
	}
	packet := make([]byte, 0, dataMinSize+len(plaintext))

	sendIndex := make([]byte, 4)

	binary.BigEndian.PutUint32(sendIndex, s.sendIndex)
	packet = append(packet, sendIndex...)

	sendCounter := make([]byte, 8)
	binary.BigEndian.PutUint64(sendCounter, s.sendCounter)
	packet = append(packet, sendCounter...)

	packet, err := aeadSeal(packet, s.sendKey, s.sendCounter, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return packet, nil
}

// DecryptPacket decrypts the data passed in and returns it in a []byte
func (s *Session) DecryptPacket(packet []byte) ([]byte, error) {
	if s.recvKey == nil {
		s.deriveDataKeys()
	}
	// ignore index, we'll use that to determine the session elsewhere
	packet = packet[4:]

	recvCounter := binary.BigEndian.Uint64(packet)
	packet = packet[8:]
	// TODO prevent replay attacks with using recvCounter
	// we'll have to deal with UDP reordering so that's a bummer
	// check how Wireguard solved it, that seems to be the theme of this project

	plaintext, err := aeadOpen(nil, s.recvKey, recvCounter, packet, nil)
	if err != nil {
		return nil, err
	}
	// we know that the packet is authentic now
	s.recvCounter = recvCounter

	return plaintext, nil
}

// MakeDataKeys fills out sendKey and revcKey for the session
func (s *Session) deriveDataKeys() error {
	sendIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(sendIndex, s.sendIndex)
	recvIndex := make([]byte, 4)
	binary.BigEndian.PutUint32(recvIndex, s.recvIndex)

	ephemSecret, err := ecdh(s.ephemPriv, s.theirEphemPub)
	if err != nil {
		return err
	}
	staticSecret, err := ecdh(s.staticPriv, s.theirStaticPub)
	if err != nil {
		return err
	}
	key, err := hash(append(ephemSecret, staticSecret...))
	if err != nil {
		return err
	}

	s.sendKey, err = deriveKey(key, sendIndex, 32)
	if err != nil {
		return err
	}
	s.recvKey, err = deriveKey(key, recvIndex, 32)
	if err != nil {
		return err
	}

	return nil
}
