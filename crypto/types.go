package crypto

import (
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
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

	hashSize       = blake2s.Size
	keySize        = chacha20poly1305.KeySize
	nonceSize      = chacha20poly1305.NonceSize
	xNonceSize     = chacha20poly1305.NonceSizeX
	emptyAeadSize  = 16
	emptyXAeadSize = 16
	macSize        = blake2s.Size128
)

var (
	// ErrDecrypt represents all decryption errors
	ErrDecrypt = errors.New("natpunch/crypto: decryption error")
	// ErrEncrypt represents all encryption errors
	ErrEncrypt = errors.New("natpunch/crypto: encryption error")
	// ErrKeysize occurs on an invalid key size
	ErrKeysize = errors.New("natpunch/crypto: key size should be 32")
	// ErrHashsize occurs on an invalid hash size
	ErrHashsize = errors.New("natpunch/crypto: hash size should be 16 or 32")
	// ErrPacket occurs on an invalid packet size
	ErrPacket = errors.New("natpunch/crypto: invalid packet")

	labelMac = []byte("mac-----")
)

// Session is an encrypted session with another party
type Session struct {

	// TODO refactor to accomodate handshakeState
	// ======================================================================

	staticPriv []byte
	staticPub  []byte

	theirStaticPub []byte

	ephemPriv []byte
	ephemPub  []byte

	theirEphemPub []byte

	// ======================================================================

	sendKey []byte
	recvKey []byte

	// TODO will be nonces in send cipherState and recv cipherState
	sendCounter uint64
	recvCounter uint64

	// TODO get these into the handshake
	sendIndex uint32
	recvIndex uint32

	// TODO get this into the handshake
	created uint64
}
