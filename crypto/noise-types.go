package crypto

// we use arrays instead of slices to reduce errors and heap allocations

const (
	protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	prologue     = "nat-punching-rocks"
)

type noiseKey [keySize]byte
type noiseHash [hashSize]byte

type keyPair struct {
	priv noiseKey
	pub  noiseKey
}

// CipherState keeps the state of a cipher with a key and nonce
type CipherState struct {
	key   noiseKey
	nonce uint64
}

// SymmetricState keeps track of the symmetric state between responder and initiator
type SymmetricState struct {
	cipher      CipherState
	chainingKey noiseKey
	hash        noiseHash
}

// HandshakeState keeps state for all data necessary for the handshake
type HandshakeState struct {
	sym        SymmetricState
	static     keyPair
	ephem      keyPair
	respStatic noiseKey
	respEphem  noiseKey
}
