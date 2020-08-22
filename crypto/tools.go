package crypto

import (
	"crypto/rand"
	"encoding/binary"
	hashLib "hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// deriveKey uses a blake2b-based HKDF to derive keys.
func deriveKey(key, salt []byte, size int) ([]byte, error) {
	// checked source, can't return err on nil key
	h, _ := blake2b.New256(nil)
	hf := func() hashLib.Hash { return h }
	keyReader := hkdf.New(hf, key, salt, nil)
	newKey := make([]byte, size)
	_, err := io.ReadFull(keyReader, newKey)
	return newKey, err
}

// zeroKeys fills all slices passed in with zeros.
func zeroKeys(keys ...[]byte) {
	for _, key := range keys {
		for i := range key {
			key[i] = 0
		}
	}
}

// aeadSeal encrypts the plaintext with the key and nonce using ChaCha20, and authorizes it with Poly1305
// dst and authtext are optional
func aeadSeal(dst, key []byte, counter uint64, plaintext, authtext []byte) ([]byte, error) {
	nonce := [12]byte{}
	binary.BigEndian.PutUint64(nonce[4:], counter)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(dst, nonce[:], plaintext, authtext), nil
}

// xAeadSeal encrypts the plaintext with the key and nonce using ChaCha20, and authorizes it with Poly1305
// dst and authtext are optional
// nonce is 24 bytes, should be random
func xAeadSeal(dst, key, nonce, plaintext, authtext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(dst, nonce, plaintext, authtext), nil
}

// aeadOpen verifies the ciphertext and authtext with Poly1305, then decrypts it with the key and nonce using ChaCha20.
// dst is optional
func aeadOpen(dst, key []byte, counter uint64, ciphertext, authtext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	nonce := [12]byte{}
	if err != nil {
		return nil, err
	}
	// var errOpen = errors.New("chacha20poly1305: message authentication failed")
	return aead.Open(dst, nonce[:], ciphertext, authtext)
}

// xAeadOpen verifies the ciphertext and authtext with Poly1305, then decrypts it with the key and nonce using ChaCha20.
// dst is optional
// nonce is 24 bytes
func xAeadOpen(dst, key, nonce, ciphertext, authtext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return aead.Open(dst, nonce, ciphertext, authtext)
}

// elliptical curve diffie-hellman with curve25519 keys
func ecdh(priv, pub []byte) ([]byte, error) {
	return curve25519.X25519(priv, pub)
}

// generates a random 32 byte key
func genPrivkey() ([]byte, error) {
	return randBytes(32)
}

// generates a 32 byte curve25519 pubkey from a 32 byte key
func genPubkey(priv []byte) ([]byte, error) {
	return curve25519.X25519(priv, curve25519.Basepoint)
}

// blake2b-256 unkeyed hash (32 bytes)
func hash(b []byte) ([]byte, error) {
	return blake2Hash(nil, b, 32)
}

// not sure if this works properly as an HMAC, disabling for now
// // blake2b-256 keyed hash (32 bytes)
// func hmac(key, b []byte) ([]byte, error) {
// 	return blake2Hash(key, b, 32)
// }

// blake2b-128 keyed hash (16 bytes)
func mac(key, b []byte) ([]byte, error) {
	return blake2Hash(key, b, 16)
}

// blake2b hash. size from 0 to 64, key can be nil
func blake2Hash(key, b []byte, size int) ([]byte, error) {
	h, err := blake2b.New(size, key)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(b)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func randBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
