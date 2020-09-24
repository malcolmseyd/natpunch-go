package network

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"log"
	"net"
	"time"
)

type RawConn struct {
	rc *ipv4.RawConn
}

// NewRawConn creates an ipv4 and udp only RawConn and applies packet filtering
func NewRawConn(client *Client) *RawConn {
	var rc RawConn

	// IPv4 only for now
	// TODO try empty address field
	packetConn, err := net.ListenPacket("ip4:udp", client.IP.String())
	if err != nil {
		log.Fatalln("Error creating packetConn:", err)
	}

	rc.rc, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Fatalln("Error creating rawConn:", err)
	}

	return &rc
}

func (rc *RawConn) SendRaw(rawPacket []byte, server *Server) error {
	_, err := rc.rc.WriteToIP(rawPacket, server.Addr)
	return err
}

func (rc *RawConn) Send(packet []byte, client *Client, server *Server) error {
	rawPacket, err := rc.makeRawPacket(packet, client, server)
	if err != nil {
		return err
	}
	return rc.SendRaw(rawPacket, server)
}

func (rc *RawConn) RecvRaw() ([]byte, int, error) {
	err := rc.rc.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, 0, err
	}
	// TODO add length field to packet
	// this will allow us to use a growable buffer, or to read only when needed
	response := make([]byte, 4096)
	n, err := rc.rc.Read(response)
	if err != nil {
		return nil, n, err
	}
	return response, n, nil
}

func (rc *RawConn) Recv() ([]byte, error) {
	buf, n, err := rc.RecvRaw()
	if err != nil {
		return nil, err
	}
	return buf[EmptyUDPSize:n], nil
}

// ApplyBPF constructs a BPF program and applies it to the RawConn
func (rc *RawConn) ApplyBPF(client *Client, server *Server) error {
	const ipv4HeaderLen = 20

	const srcIPOffset = 12
	const srcPortOffset = ipv4HeaderLen + 0
	const dstPortOffset = ipv4HeaderLen + 2

	ipInt := binary.BigEndian.Uint32(server.Addr.IP.To4())

	// we don't need to filter packet type because the rawconn is ipv4-udp only
	// Skip values represent the number of instructions to skip if true or false
	// We can skip to the end if we get a !=, otherwise keep going
	bpfRaw, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: srcIPOffset, Size: 4}, //src ip is server
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipInt, SkipFalse: 5, SkipTrue: 0},

		bpf.LoadAbsolute{Off: srcPortOffset, Size: 2}, //src port is server
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(server.Port), SkipFalse: 3, SkipTrue: 0},

		bpf.LoadAbsolute{Off: dstPortOffset, Size: 2}, //dst port is client
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(client.Port), SkipFalse: 1, SkipTrue: 0},

		bpf.RetConstant{Val: 1<<(8*4) - 1}, // max number that fits this value (entire packet)
		bpf.RetConstant{Val: 0},            // drop packet
	})

	err = rc.rc.SetBPF(bpfRaw)
	if err != nil {
		return err
	}
	return nil
}

// makePacket constructs a request packet to send to the server
func (rc *RawConn) makeRawPacket(payload []byte, client *Client, server *Server) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()

	// this does the hard stuff for us
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipHeader := layers.IPv4{
		SrcIP:    client.IP,
		DstIP:    server.Addr.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udpHeader := layers.UDP{
		SrcPort: layers.UDPPort(client.Port),
		DstPort: layers.UDPPort(server.Port),
	}

	payloadLayer := gopacket.Payload(payload)

	err := udpHeader.SetNetworkLayerForChecksum(&ipHeader)
	if err != nil {
		return nil, err
	}

	err = gopacket.SerializeLayers(buf, opts, &ipHeader, &udpHeader, &payloadLayer)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (rc *RawConn) Close() error {
	return rc.rc.Close()
}
