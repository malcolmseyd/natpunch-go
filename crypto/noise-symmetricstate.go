package crypto

// Initialize fills out the appropriate fields in SymmetriState
func (s *SymmetricState) Initialize(protocol []byte) {
	s.hash = hashFunc(protocol)
	s.chainingKey = noiseKey(s.hash)
}

// MixKey mixes chaining key with input data
func (s *SymmetricState) MixKey(input []byte) {
	var tmp noiseKey
	s.chainingKey, tmp, _ = deriveKeys(s.chainingKey, input)
	s.cipher.InitializeKey(tmp)
}

// MixHash mixes hash with input data
func (s *SymmetricState) MixHash(input []byte) {
	s.hash = hashFunc(append(s.hash[:], input...))
}

// MixKeyAndHash mixes key and hash with input data
func (s *SymmetricState) MixKeyAndHash(input []byte) {
	var tmpHash noiseKey
	var tmpKey noiseKey
	s.chainingKey, tmpHash, tmpKey = deriveKeys(s.chainingKey, input)
	s.MixHash(tmpHash[:])
	s.cipher.InitializeKey(tmpKey)
}

// GetHandshakeHash returns SymmetricState's hash as a byte slice
func (s *SymmetricState) GetHandshakeHash() []byte {
	return s.hash[:]
}

// EncryptAndHash encrypts the plaintext, hashes it, and returns the ciphertext
func (s *SymmetricState) EncryptAndHash(plaintext []byte) (ciphertext []byte) {
	ciphertext = s.cipher.EncryptWithAd(s.hash[:], plaintext)
	s.MixHash(ciphertext)
	return
}

// DecryptAndHash decrypts the ciphertext, hashes it, and returns the plaintext
func (s *SymmetricState) DecryptAndHash(ciphertext []byte) (plaintext []byte, err error) {
	plaintext, err = s.cipher.DecryptWithAd(s.hash[:], ciphertext)
	if err != nil {
		return
	}
	s.MixHash(ciphertext)
	return
}

// Split returns a pair of CipherStates for encrypting transport messages
func (s *SymmetricState) Split() (cipher1, cipher2 CipherState) {
	tmpKey1, tmpKey2, _ := deriveKeys(s.chainingKey, nil)
	cipher1.InitializeKey(tmpKey1)
	cipher2.InitializeKey(tmpKey2)
	return
}
