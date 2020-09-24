package network

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/flynn/noise"
	"github.com/malcolmseyd/natpunch-go/client/auth"
	"time"
)

// Handshake performs a Noise-IK handshake with the Server
func (c *Conn) Handshake() error {
	index, err := c.newIndex()
	if err != nil {
		return err
	}
	config, err := auth.NewConfig(c.client.Privkey, c.server.Pubkey)
	if err != nil {
		return err
	}
	handshake, err := noise.NewHandshakeState(config)
	if err != nil {
		return err
	}

	packet, err := newHandshakeInit(index, handshake)
	if err != nil {
		return err
	}
	err = c.Send(packet)
	if err != nil {
		return err
	}

	response, err := c.Recv()
	if err != nil {
		return err
	}

	return c.parseHandshakeResp(response, handshake)
}

// newIndex generates a random index, stores it in c.sess, and returns the byte representation
func (c *Conn) newIndex() ([]byte, error) {
	// we generate index on the client side
	indexBytes := make([]byte, 4)
	_, err := rand.Read(indexBytes)
	if err != nil {
		return nil, err
	}
	c.sess.index = binary.BigEndian.Uint32(indexBytes)

	return indexBytes, nil
}

// newHandshakeInit creates a handshake initiator packet
func newHandshakeInit(index []byte, handshake *noise.HandshakeState) ([]byte, error) {
	header := append([]byte{PacketHandshakeInit}, index...)

	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))

	packet, _, _, err := handshake.WriteMessage(header, timestamp)
	return packet, err
}

// parseHandshakeResp parses the handshake responder packet and saves the relevant data to Conn
func (c *Conn) parseHandshakeResp(response []byte, handshake *noise.HandshakeState) error {
	packetType := response[0]
	response = response[1:]

	if packetType != PacketHandshakeResp {
		return ErrPacketType
	}
	c.sess.index = binary.BigEndian.Uint32(response[:4])
	response = response[4:]

	_, send, recv, err := handshake.ReadMessage(nil, response)
	if err != nil {
		return err
	}
	// we use our own implementation for manual nonce control
	c.sess.send = auth.NewCipherState(send.Cipher())
	c.sess.recv = auth.NewCipherState(recv.Cipher())
	c.server.LastHandshake = time.Now()

	return nil
}
