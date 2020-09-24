package network

import (
	"encoding/binary"
	"github.com/malcolmseyd/natpunch-go/client/auth"
)

type session struct {
	index      uint32
	send, recv *auth.CipherState
}

type Conn struct {
	rc     *RawConn
	client *Client
	server *Server
	sess   *session
}

func NewConn(server *Server, client *Client) *Conn {
	var c Conn
	c.rc = NewRawConn(client)
	c.client = client
	c.server = server
	return &c
}

// Send sends a plain UDP packet to the Server
func (c *Conn) Send(packet []byte) error {
	return c.rc.Send(packet, c.client, c.server)
}

// SendData encrypts and sends packet to the Server
func (c *Conn) SendData(data []byte) error {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, c.sess.index)

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, c.sess.send.Nonce())

	header := append([]byte{PacketData}, indexBytes...)
	header = append(header, nonceBytes...)

	packet := c.sess.send.Encrypt(header, nil, data)

	return c.Send(packet)
}

// Recv receives a UDP packet from server
func (c *Conn) Recv() (buf []byte, err error) {
	return c.rc.Recv()
}

// RecvData receives a UDP packet from server
func (c *Conn) RecvData() (body []byte, packetType byte, n int, err error) {
	response, err := c.Recv()
	if err != nil {
		return
	}
	// println(hex.Dump(response))

	packetType = response[0]
	response = response[1:]

	nonce := binary.BigEndian.Uint64(response[:8])
	response = response[8:]
	c.sess.recv.SetNonce(nonce)

	body, err = c.sess.recv.Decrypt(nil, nil, response)
	if err != nil {
		return
	}

	// now that we're authenticated, see if the nonce is valid
	// the sliding window contains a generous 1000 packets, that should hold up
	// with plenty of peers.
	if !c.sess.recv.CheckNonce(nonce) {
		err = ErrNonce
		body = nil
	}

	return
}

func (c *Conn) Close() error {
	return c.rc.Close()
}
