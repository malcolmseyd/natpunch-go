package crypto

// ConstructHandshakeReq creates a handshake request packet from a session
// func (s *Session) ConstructHandshakeReq() ([]byte, error) {
// 	var err error
// 	packet := make([]byte, 0, handshakeReqSize)

// 	sendIndex := make([]byte, 4)
// 	binary.BigEndian.PutUint32(sendIndex, s.sendIndex)
// 	packet = append(packet, sendIndex...)

// 	s.created = uint64(time.Now().UnixNano())
// 	timestamp := make([]byte, 8)
// 	binary.BigEndian.PutUint64(timestamp, s.created)

// 	binary.BigEndian.PutUint32(packet, s.sendIndex)
// 	packet = append(packet, s.ephemPub...)

// 	// seal staticPub
// 	secret, err := dhFunc(s.ephemPriv, s.theirStaticPub)
// 	if err != nil {
// 		return nil, err
// 	}
// 	keys, err := deriveKeys(secret, sendIndex, 1)
// 	if err != nil {
// 		return nil, err
// 	}
// 	packet, err = encryptFunc(packet, keys[0], 0, s.staticPub, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// seal timestamp
// 	secret, err = dhFunc(s.staticPriv, s.theirStaticPub)
// 	if err != nil {
// 		return nil, err
// 	}
// 	keys, err = deriveKeys(secret, sendIndex, 1)
// 	if err != nil {
// 		return nil, err
// 	}
// 	packet, err = encryptFunc(packet, keys[0], 0, timestamp, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// calculate MAC with staticPub
// 	tmp, err := hashFunc(append(labelMac, s.staticPub...))
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

// // ParseHandshakeReq parses a handshake request packet into an existing session
// func (s *Session) ParseHandshakeReq(packet []byte) error {
// 	if len(packet) != handshakeReqSize {
// 		return ErrPacket
// 	}

// 	var err error
// 	curr := packet

// 	// open staticPub
// 	recvIndexBytes := curr[:4]
// 	curr = curr[4:]
// 	recvIndex := binary.BigEndian.Uint32(recvIndexBytes)

// 	theirEphemPub := curr[:32]
// 	curr = curr[32:]

// 	secret, err := dhFunc(s.staticPriv, theirEphemPub)
// 	if err != nil {
// 		return err
// 	}
// 	keys, err := deriveKeys(secret, recvIndexBytes, 1)
// 	if err != nil {
// 		return err
// 	}
// 	theirStaticPub, err := decryptFunc(nil, keys[0], 0, curr[:32+emptyAeadSize], nil)
// 	if err != nil {
// 		return err
// 	}
// 	curr = curr[32+emptyAeadSize:]

// 	// verify MAC with staticPub
// 	tmp, err := hashFunc(append(labelMac, s.theirStaticPub...))
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

// 	// open timestamp
// 	secret, err = dhFunc(s.staticPriv, s.theirStaticPub)
// 	if err != nil {
// 		return err
// 	}
// 	keys, err = deriveKeys(secret, recvIndexBytes, 1)
// 	if err != nil {
// 		return err
// 	}
// 	timestamp, err := decryptFunc(nil, keys[0], 0, curr[:8+emptyAeadSize], nil)
// 	if err != nil {
// 		return err
// 	}

// 	// identity fully verified, we can record values now
// 	s.recvIndex = recvIndex
// 	s.theirEphemPub = theirEphemPub
// 	s.theirStaticPub = theirStaticPub
// 	s.created = binary.BigEndian.Uint64(timestamp)

// 	return nil
// }
