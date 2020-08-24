package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// deriveKeys uses a blake2s-based HKDF to derive keys.
func deriveKeys(inputKey noiseKey, salt []byte) (key1, key2, key3 noiseKey) {
	keyReader := hkdf.New(blake2s256Unkeyed, inputKey[:], salt, nil)
	// should never reach entropy limit with 32 bytes of input
	// and only 3 keys generated, we can supress errors for simplicity
	io.ReadFull(keyReader, key1[:])
	io.ReadFull(keyReader, key2[:])
	io.ReadFull(keyReader, key3[:])
	return
}

func rekey(key noiseKey) (newKey noiseKey) {
	zeros := [32]byte{}
	tmp := encryptFunc(nil, key, 1<<64-1, zeros[:], nil)
	copy(newKey[:], tmp[:keySize])
	return
}

// zeroBytes fills all slices passed in with zeros.
func zeroBytes(keys ...[]byte) {
	for _, key := range keys {
		for i := range key {
			key[i] = 0
		}
	}
}

// encryptFunc encrypts the plaintext with the key and nonce using ChaCha20, and authorizes it with Poly1305
// dst and authtext are optional
func encryptFunc(dst []byte, key noiseKey, counter uint64, plaintext, authtext []byte) []byte {
	nonce := [12]byte{}
	// Noise specifies little endian nonce for ChaCha20
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	// can supress error, key[:] is guaranteed to be 32 bytes
	aead, _ := chacha20poly1305.New(key[:])
	return aead.Seal(dst, nonce[:], plaintext, authtext)
}

// decryptFunc verifies the ciphertext and authtext with Poly1305, then decrypts it with the key and nonce using ChaCha20.
// dst is optional
func decryptFunc(dst []byte, key noiseKey, counter uint64, ciphertext, authtext []byte) ([]byte, error) {
	// can supress error, key[:] is guaranteed to be 32 bytes
	aead, _ := chacha20poly1305.New(key[:])
	nonce := [12]byte{}
	// Noise specifies little endian nonce for ChaCha20
	binary.LittleEndian.PutUint64(nonce[4:], counter)

	// unless ciphertext is massive (definitely can't fit i packet), the only possible error will be decryption related
	return aead.Open(dst, nonce[:], ciphertext, authtext)
}

// elliptical curve diffie-hellman with curve25519 keys
func dhFunc(priv, pub noiseKey) ([]byte, error) {
	// noise keys should be clamped on generation,
	// therefore no error should be possible
	return curve25519.X25519(priv[:], pub[:])
}

// generates a random 32 byte key
func genPrivkey() (key noiseKey, err error) {
	_, err = rand.Read(key[:])
	key.clamp()
	return
}

// generates a 32 byte curve25519 pubkey from a 32 byte key
func genPubkey(priv noiseKey) (pub noiseKey, err error) {
	result, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	copy(pub[:], result)
	return
}

// generate keyPair from random bytes and curve25519
func genKeyPair() (keyPair, error) {
	k := keyPair{}
	rand.Read(k.priv[:])
	var err error
	k.pub, err = genPubkey(k.priv)
	if err != nil {
		return k, err
	}
	return k, nil
}

// blake2s-256 unkeyed hashFunc (32 bytes)
func hashFunc(b []byte) noiseHash {
	return blake2s.Sum256(b)
}

// blake2s-256 HMAC (32 bytes)
func hmacFunc(key noiseKey, b []byte) (sum noiseHash) {
	h := hmac.New(blake2s256Unkeyed, key[:])
	// blake2s digest.Write never returns err
	_, _ = h.Write(b)
	result := h.Sum(nil)
	copy(sum[:], result)
	return sum
}

// blake2s-128 keyed hash (16 bytes)
func macFunc(key noiseKey, b []byte) []byte {
	h, _ := blake2s.New128(key[:])
	h.Write(b)
	return h.Sum(nil)
}

// blake2s hash for HMAC and HKDF functions
func blake2s256Unkeyed() hash.Hash {
	// this can't return an error if key is nil
	h, _ := blake2s.New256(nil)
	return h
}
