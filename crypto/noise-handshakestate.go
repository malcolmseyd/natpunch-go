package crypto

// Initialize sets up the inital state for the handshake
func (h *HandshakeState) Initialize(ourPriv, theirPub [32]byte) (err error) {
	h.sym.Initialize([]byte(protocolName))
	h.sym.MixHash([]byte(prologue))

	h.static.priv = ourPriv
	h.static.pub, err = genPubkey(h.static.priv)
	if err != nil {
		return err
	}

	err = h.ephem.generate()
	if err != nil {
		return err
	}

	h.respStatic = theirPub

	h.sym.MixHash(theirPub[:])

	return nil
}
