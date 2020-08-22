package crypto

import (
	"encoding/binary"
)

// EncryptPacket encrypts the data passed in and returns it in a []byte
func (s *Session) EncryptPacket(data []byte) ([]byte, error) {
	// TODO write the function
	return nil, nil
}

// DecryptPacket decrypts the data passed in and returns it in a []byte
func (s *Session) DecryptPacket(encrypted []byte) ([]byte, error) {
	// TODO write the function
	return nil, nil
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
