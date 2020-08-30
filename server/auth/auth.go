package auth

import (
	"crypto/rand"

	"github.com/flynn/noise"
	"github.com/malcolmseyd/natpunch-go/antireplay"
	"golang.org/x/crypto/curve25519"
)

var noiseConfig = noise.Config{
	CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
	Random:      rand.Reader,
	Pattern:     noise.HandshakeIK,
	Initiator:   false,
	Prologue:    []byte("natpunch-go is the best :)"),
}

// CipherState is an alternate implementation of noise.CipherState
// that allows manual control over the nonce
type CipherState struct {
	c noise.Cipher
	n uint64
	w antireplay.Window
}

// NewCipherState initializes a new CipherState
func NewCipherState(c noise.Cipher) *CipherState {
	return &CipherState{c: c}
}

// Encrypt is the same as noise.HandshakeState
func (s *CipherState) Encrypt(out, ad, plaintext []byte) []byte {
	out = s.c.Encrypt(out, s.n, ad, plaintext)
	s.n++
	return out
}

// Decrypt is the same as noise.HandshakeState
func (s *CipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	out, err := s.c.Decrypt(out, s.n, ad, ciphertext)
	s.n++
	return out, err
}

// Nonce returns the nonce value inside CipherState
func (s *CipherState) Nonce() uint64 {
	return s.n
}

// SetNonce sets the nonce value inside CipherState
func (s *CipherState) SetNonce(n uint64) {
	s.n = n
}

// CheckNonce returns true if the nonce is valid, and false if the nonce is
// reused or outside of the sliding window
func (s *CipherState) CheckNonce(n uint64) bool {
	return s.w.Check(n)
}

// NewConfig initializes a new noise.Config with the provided data
func NewConfig(privkey, theirPubkey [32]byte) (config noise.Config, err error) {
	config = noiseConfig
	config.StaticKeypair = noise.DHKey{
		Private: privkey[:],
	}
	config.StaticKeypair.Public, err = curve25519.X25519(config.StaticKeypair.Private, curve25519.Basepoint)
	if err != nil {
		return config, err
	}
	config.PeerStatic = theirPubkey[:]
	return
}
