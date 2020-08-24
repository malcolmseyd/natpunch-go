package crypto

// InitializeKey initializes CipherState with a key
func (c *CipherState) InitializeKey(key noiseKey) {
	c.key = key
	c.nonce = 0
}

// HasKey returns whether the CipherState has a key
func (c *CipherState) HasKey() bool {
	return c.key.isEmpty()
}

// SetNonce sets the nonce for the CipherState
func (c *CipherState) SetNonce(nonce uint64) {
	c.nonce = nonce
}

// EncryptWithAd encrypts plaintext with optional authentication data
func (c *CipherState) EncryptWithAd(authData, plaintext []byte) []byte {
	if c.key.isEmpty() {
		return plaintext
	}
	encrypted := encryptFunc(nil, c.key, c.nonce, plaintext, authData)
	c.nonce++
	return encrypted
}

// DecryptWithAd decrypts ciphertext with optional authentication data
func (c *CipherState) DecryptWithAd(authData, ciphertext []byte) ([]byte, error) {
	if c.key.isEmpty() {
		return ciphertext, nil
	}
	plaintext, err := decryptFunc(nil, c.key, c.nonce, ciphertext, authData)
	if err != nil {
		return nil, err
	}
	c.nonce++
	return plaintext, err
}

// Rekey is a pseudorandom function that replaces the key with a new one
func (c *CipherState) Rekey() {
	c.key = rekey(c.key)
}
