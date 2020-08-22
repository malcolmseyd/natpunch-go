package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
)

const (
	// PacketHandshakeReq is a handshake request
	PacketHandshakeReq = 1
	// PacketHandshakeResp is a handshake response
	PacketHandshakeResp = 2
	// PacketData is a data packet
	PacketData = 3

	// index + ephemPub + encrypted staticPub + encrypted timestamp + MAC
	handshakeReqSize  = 4 + 32 + (32 + emptyAeadSize) + (8 + emptyAeadSize) + 16
	handshakeRespSize = 4 + 4 + 32 + emptyAeadSize + 16
	dataMinSize       = 4 + 8 + 16

	keysize        = 32
	nonceSize      = 12
	xNonceSize     = 24
	emptyAeadSize  = 16
	emptyXAeadSize = 16
	macSize        = 16
)

var (
	// ErrDecrypt represents all decryption errors
	ErrDecrypt = errors.New("natpunch/crypto: decryption error")
	// ErrEncrypt represents all encryption errors
	ErrEncrypt = errors.New("natpunch/crypto: encryption error")
	// ErrKeysize occurs on an invalid key size
	ErrKeysize = errors.New("natpunch/crypto: key size should be 32")
	// ErrPacket occurs on an invalid packet size
	ErrPacket = errors.New("natpunch/crypto: invalid packet")

	labelMac = []byte("mac-----")
)

// Session is an encrypted session with another party
type Session struct {
	staticPriv []byte
	staticPub  []byte

	theirStaticPub []byte

	ephemPriv []byte
	ephemPub  []byte

	theirEphemPub []byte

	sendKey     []byte
	sendIndex   uint32
	sendCounter uint64

	recvKey     []byte
	recvIndex   uint32
	recvCounter uint64

	created uint64
}

// NewSession creates a new Session object and returns a pointer
func NewSession(priv []byte, theirPub []byte) (*Session, error) {
	if len(priv) != 32 || len(theirPub) != 32 {
		return nil, ErrKeysize
	}

	var err error
	s := Session{
		staticPriv:     priv,
		theirStaticPub: theirPub,
	}

	s.ephemPriv, err = genPrivkey()
	if err != nil {
		return nil, err
	}
	s.ephemPub, err = genPubkey(s.ephemPriv)
	if err != nil {
		return nil, err
	}

	// do the work only once
	s.staticPub, err = genPubkey(priv)
	if err != nil {
		return nil, err
	}
	s.sendCounter = 0
	//  non-zero for testing, shouldn't be a problem practically
	for s.sendIndex == 0 {
		err = binary.Read(rand.Reader, binary.BigEndian, &s.sendIndex)
		if err != nil {
			return nil, err
		}
	}
	return &s, nil
}

// String is for debugging purposes.
func (s *Session) String() string {
	str := "== session ==\n"
	str += "static privkey: " + base64.StdEncoding.EncodeToString(s.staticPriv) + "\n"
	str += "static pubkey:  " + base64.StdEncoding.EncodeToString(s.staticPub) + "\n"
	str += "\n"
	str += "ephemeral privkey: " + base64.StdEncoding.EncodeToString(s.ephemPriv) + "\n"
	str += "ephemeral pubkey:  " + base64.StdEncoding.EncodeToString(s.ephemPub) + "\n"
	str += "\n"
	str += "index:   " + strconv.FormatUint(uint64(s.sendIndex), 10) + "\n"
	str += "counter: " + strconv.FormatUint(uint64(s.sendIndex), 10) + "\n"
	return str
}

// CountSend increments the send counter. This should be called when a packet is successfully sent.
// There's no CountRecv because the packet needs to be verified upon decryption before we increment that.
func (s *Session) CountSend() {
	s.sendCounter++
}
