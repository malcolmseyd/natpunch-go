package crypto

// ConstructHandshakeResp constructs a handshake response packet from the session
// func (s *Session) ConstructHandshakeResp() ([]byte, error) {
// 	var err error
// 	packet := make([]byte, 0, handshakeRespSize)

// 	sendIndex := make([]byte, 4)
// 	binary.BigEndian.PutUint32(sendIndex, s.sendIndex)
// 	packet = append(packet, sendIndex...)

// 	recvIndex := make([]byte, 4)
// 	binary.BigEndian.PutUint32(recvIndex, s.recvIndex)
// 	packet = append(packet, recvIndex...)

// 	packet = append(packet, s.ephemPub...)

// 	// ephem-ephem secret
// 	secret, err := dhFunc(s.ephemPriv, s.theirEphemPub)
// 	if err != nil {
// 		return nil, err
// 	}
// 	keys, err := deriveKeys(secret, sendIndex, 1)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// static-static secret
// 	secret, err = dhFunc(s.staticPriv, s.theirStaticPub)
// 	if err != nil {
// 		return nil, err
// 	}
// 	keys, err = deriveKeys(secret, keys[0], 1)
// 	if err != nil {
// 		return nil, err
// 	}
// 	packet, err = encryptFunc(packet, keys[0], s.sendCounter, nil, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	tmp, err := hashFunc(append(labelMac, s.theirStaticPub...))
// 	if err != nil {
// 		return nil, err
// 	}
// 	macBytes, err := macFunc(tmp, packet)
// 	if err != nil {
// 		return nil, err
// 	}
// 	packet = append(packet, macBytes...)
// 	return packet, nil
// }

// // ParseHandshakeResp parses a handshake response packet into an existing session
// func (s *Session) ParseHandshakeResp(packet []byte) error {
// 	if len(packet) != handshakeRespSize {
// 		return ErrPacket
// 	}

// 	var err error
// 	curr := packet

// 	recvIndex := curr[:4]
// 	curr = curr[4:]

// 	// ignore sender index, used to ID the packet
// 	curr = curr[4:]

// 	theirEphemPub := curr[:32]
// 	curr = curr[32:]

// 	tmp, err := hashFunc(append(labelMac, s.staticPub...))
// 	if err != nil {
// 		return err
// 	}
// 	macOffset := len(packet) - macSize
// 	macBytes, err := macFunc(tmp, packet[:macOffset])
// 	if err != nil {
// 		return err
// 	}
// 	if subtle.ConstantTimeCompare(macBytes, packet[macOffset:]) == 0 {
// 		return ErrDecrypt
// 	}

// 	// open empty AEAD
// 	// ephem-ephem secret
// 	secret, err := dhFunc(s.ephemPriv, theirEphemPub)
// 	if err != nil {
// 		return err
// 	}
// 	keys, err := deriveKeys(secret, recvIndex, 1)
// 	if err != nil {
// 		return err
// 	}
// 	// static-static secret
// 	secret, err = dhFunc(s.staticPriv, s.theirStaticPub)
// 	if err != nil {
// 		return err
// 	}
// 	keys, err = deriveKeys(secret, keys[0], 1)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = decryptFunc(nil, keys[0], 0, curr[:emptyAeadSize], nil)
// 	if err != nil {
// 		return err
// 	}

// 	// identity verified, ok to record values now
// 	s.recvIndex = binary.BigEndian.Uint32(recvIndex)
// 	s.theirEphemPub = theirEphemPub

// 	return nil
// }
