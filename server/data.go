package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// TODO timeout properly
func (s *state) dataPacket(packet []byte, clientAddr *net.UDPAddr, timeout time.Duration) (err error) {
	index := binary.BigEndian.Uint32(packet[:4])
	packet = packet[4:]

	client, ok := s.indexMap[index]
	if !ok {
		return
	}

	nonce := binary.BigEndian.Uint64(packet[:8])
	packet = packet[8:]

	client.recv.SetNonce(nonce)
	plaintext, err := client.recv.Decrypt(nil, nil, packet)
	if err != nil {
		return
	}
	if !client.recv.CheckNonce(nonce) {
		// no need to throw an error, just return
		return
	}

	clientPubKey := plaintext[:32]
	plaintext = plaintext[32:]

	if !bytes.Equal(clientPubKey, client.pubkey[:]) {
		err = ErrPubkey
		return
	}

	var targetPubKey Key
	copy(targetPubKey[:], plaintext[:32])
	// for later use
	plaintext = plaintext[:6]

	client.ip = clientAddr.IP
	client.port = uint16(clientAddr.Port)

	targetPeer, peerExists := s.keyMap[targetPubKey]
	if peerExists {
		// client must be ipv4 so this will never return nil
		copy(plaintext[:4], targetPeer.ip.To4())
		binary.BigEndian.PutUint16(plaintext[4:6], targetPeer.port)
	} else {
		// return nothing if peer not found
		plaintext = plaintext[:0]
	}

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, client.send.Nonce())

	header := append([]byte{PacketData}, nonceBytes...)
	// println("sent nonce:", client.send.Nonce())
	// println("sending", len(plaintext), "bytes")
	response := client.send.Encrypt(header, nil, plaintext)

	_, err = s.conn.WriteToUDP(response, clientAddr)
	if err != nil {
		return
	}

	fmt.Print(
		base64.StdEncoding.EncodeToString(client.pubkey[:])[:16],
		" ==> ",
		base64.StdEncoding.EncodeToString(targetPubKey[:])[:16],
		": ",
	)

	if peerExists {
		fmt.Println("CONNECTED")
	} else {
		fmt.Println("NOT FOUND")
	}

	return
}
