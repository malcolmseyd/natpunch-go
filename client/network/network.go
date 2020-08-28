package network

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/flynn/noise"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/malcolmseyd/natpunch-go/client/auth"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const (
	udpProtocol = 17
	// EmptyUDPSize is the size of an empty UDP packet
	EmptyUDPSize = 28

	// PacketHandshakeInit identifies handhshake initiation packets
	PacketHandshakeInit byte = 1
	// PacketHandshakeResp identifies handhshake response packets
	PacketHandshakeResp byte = 2
	// PacketData identifies regular data packets
	PacketData byte = 3
)

var (
	// ErrPacketType is returned when an unexepcted packet type is enountered
	ErrPacketType = errors.New("client/network: incorrect packet type")
)

// EmptyUDPSize is the size of the IPv4 and UDP headers combined.

// Key stores a 32 byte representation of a Wireguard key
type Key [32]byte

// Server stores data relating to the server
type Server struct {
	Hostname string
	Addr     *net.IPAddr
	Port     uint16
	Pubkey   Key
}

// Peer stores data about a peer's key and endpoint, whether it's another peer or the client
// While Resolved == false, we consider IP and Port to be uninitialized
// I could have done a nested struct with Endpoint containing IP and Port but that's
// unnecessary right now.
type Peer struct {
	Resolved bool
	IP       net.IP
	Port     uint16
	Pubkey   Key
}

// GetClientIP gets source ip address that will be used when sending data to dstIP
func GetClientIP(dstIP net.IP) net.IP {
	// i wanted to use gopacket/routing but it breaks when the vpn iface is already up
	routes, err := netlink.RouteGet(dstIP)
	if err != nil {
		log.Fatalln("Error getting route:", err)
	}
	// pick the first one cuz why not
	return routes[0].Src
}

// HostToAddr resolves a hostname, whether DNS or IP to a valid net.IPAddr
func HostToAddr(hostStr string) *net.IPAddr {
	remoteAddrs, err := net.LookupHost(hostStr)
	if err != nil {
		log.Fatalln("Error parsing remote address:", err)
	}

	for _, addrStr := range remoteAddrs {
		if remoteAddr, err := net.ResolveIPAddr("ip4", addrStr); err == nil {
			return remoteAddr
		}
	}
	return nil
}

// SetupRawConn creates an ipv4 and udp only RawConn and applies packet filtering
func SetupRawConn(server *Server, client *Peer) *ipv4.RawConn {
	packetConn, err := net.ListenPacket("ip4:udp", client.IP.String())
	if err != nil {
		log.Fatalln("Error creating packetConn:", err)
	}

	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Fatalln("Error creating rawConn:", err)
	}

	ApplyBPF(rawConn, server, client)

	return rawConn
}

// ApplyBPF constructs a BPF program and applies it to the RawConn
func ApplyBPF(rawConn *ipv4.RawConn, server *Server, client *Peer) {
	const ipv4HeaderLen = 20

	const srcIPOffset = 12
	const srcPortOffset = ipv4HeaderLen + 0
	const dstPortOffset = ipv4HeaderLen + 2

	ipArr := []byte(server.Addr.IP.To4())
	ipInt := uint32(ipArr[0])<<(3*8) + uint32(ipArr[1])<<(2*8) + uint32(ipArr[2])<<8 + uint32(ipArr[3])

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
		bpf.RetConstant{Val: 0},
	})

	err = rawConn.SetBPF(bpfRaw)
	if err != nil {
		log.Fatalln("Error setting BPF:", err)
	}
}

// MakePacket constructs a request packet to send to the server
func MakePacket(payload []byte, server *Server, client *Peer) []byte {
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

	udpHeader.SetNetworkLayerForChecksum(&ipHeader)

	gopacket.SerializeLayers(buf, opts, &ipHeader, &udpHeader, &payloadLayer)

	return buf.Bytes()
}

// Handshake performs a Noise-IK handshake with the Server
func Handshake(conn *ipv4.RawConn, timeout time.Duration, privkey Key, server *Server, client *Peer) (sendCipher, recvCipher *auth.CipherState, index uint32, err error) {
	// we generate index on the client side
	indexBytes := make([]byte, 4)
	rand.Read(indexBytes)
	index = binary.BigEndian.Uint32(indexBytes)

	config, err := auth.NewConfig(privkey, server.Pubkey)
	if err != nil {
		return
	}

	handshake, err := noise.NewHandshakeState(config)
	if err != nil {
		return
	}

	header := append([]byte{PacketHandshakeInit}, indexBytes...)

	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))

	packet, _, _, err := handshake.WriteMessage(header, timestamp)
	if err != nil {
		return
	}
	err = SendPacket(packet, conn, server, client)
	if err != nil {
		return
	}

	response, n, err := RecvPacket(conn, timeout, server, client)
	if err != nil {
		return
	}
	response = response[EmptyUDPSize:n]
	packetType := response[0]
	response = response[1:]

	if packetType != PacketHandshakeResp {
		err = ErrPacketType
		return
	}
	index = binary.BigEndian.Uint32(response[:4])
	response = response[4:]

	_, send, recv, err := handshake.ReadMessage(nil, response)
	// we use our own implementation for manual nonce control
	sendCipher = auth.NewCipherState(send.Cipher())
	recvCipher = auth.NewCipherState(recv.Cipher())

	return
}

// SendPacket sends packet to the Server
func SendPacket(packet []byte, conn *ipv4.RawConn, server *Server, client *Peer) error {
	fullPacket := MakePacket(packet, server, client)
	_, err := conn.WriteToIP(fullPacket, server.Addr)
	return err
}

// SendDataPacket encrypts and sends packet to the Server
func SendDataPacket(cipher *auth.CipherState, index uint32, data []byte, conn *ipv4.RawConn, server *Server, client *Peer) error {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)

	nonceBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(nonceBytes, cipher.Nonce())
	// println("sending nonce:", cipher.Nonce())

	header := append([]byte{PacketData}, indexBytes...)
	header = append(header, nonceBytes...)

	packet := cipher.Encrypt(header, nil, data)

	return SendPacket(packet, conn, server, client)
}

// RecvPacket recieves a UDP packet from server
func RecvPacket(conn *ipv4.RawConn, timeout time.Duration, server *Server, client *Peer) ([]byte, int, error) {
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, 0, err
	}
	// TODO add length field to packet
	// this will allow us to use a growable buffer, or to read only when needed
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, n, err
	}
	return response, n, nil
}

// RecvDataPacket recieves a UDP packet from server
func RecvDataPacket(cipher *auth.CipherState, conn *ipv4.RawConn, timeout time.Duration, server *Server, client *Peer) (body, header []byte, packetType byte, n int, err error) {
	response, n, err := RecvPacket(conn, timeout, server, client)
	if err != nil {
		return
	}
	header = response[:EmptyUDPSize]
	response = response[EmptyUDPSize:n]
	// println(hex.Dump(response))

	packetType = response[0]
	response = response[1:]

	// TODO sliding window for nonce
	// this is vulnerable to nonce reuse and replay attacks.
	// due to UDP reordering we cannot use a conventional implementation
	// and will have to rely on a sliding window of sorts. since we can
	// predict the number of response packets that shouldn't be too hard
	nonce := binary.BigEndian.Uint64(response[:8])
	response = response[8:]
	cipher.SetNonce(nonce)
	// println("recving nonce:", nonce)

	body, err = cipher.Decrypt(nil, nil, response)
	return
}

// ParseResponse takes a response packet and parses it into an IP and port.
// There's no error checking, we assume that data passed in is valid
func ParseResponse(response []byte) (net.IP, uint16) {
	var ip net.IP
	var port uint16
	// packet := gopacket.NewPacket(response, layers.LayerTypeIPv4, gopacket.DecodeOptions{
	// 	Lazy:   true,
	// 	NoCopy: true,
	// })
	// if packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
	// 	return nil, 0
	// }
	// payload := packet.ApplicationLayer().LayerContents()

	// data := bytes.NewBuffer(payload)
	// // fmt.Println("Layer payload:\n", hex.Dump(data.Bytes()))

	// binary.Read(data, binary.BigEndian, &ipv4Slice)
	// ip = net.IP(ipv4Slice)
	// binary.Read(data, binary.BigEndian, &port)
	// // fmt.Println("ip:", ip.String(), "port:", port)
	ip = net.IP(response[:4])
	port = binary.BigEndian.Uint16(response[4:6])
	return ip, port
}

func testBPF(peers []Peer, client *Peer, server *Server, rawConn *ipv4.RawConn) {
	payload := make([]byte, 64)
	copy(payload[0:32], client.Pubkey[:])

	response := make([]byte, 4096)

	// goroutine to read replies
	go func() {
		for {
			n, err := rawConn.Read(response)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					fmt.Println("\nConnection to", server.Hostname, "timed out.")
					continue
				}
				fmt.Println("\nError receiving packet:", err)
				continue
			}
			// fmt.Println(n-28, "bytes read")
			if n != 28 && n != 28+6 {
				srcIP, srcPort, dstPort := parseForBPF(response)
				fmt.Println("\nInvalid response of", n, "bytes")
				fmt.Println("SRC IP:", srcIP, "\tEXPECTED:", server.Addr.IP)
				fmt.Println("SRC PORT:", srcPort, "\tEXPECTED:", server.Port)
				fmt.Println("DST PORT:", dstPort, "\tEXPECTED:", client.Port)
				fmt.Println()
				// fmt.Println(hex.Dump(response[:n]))
			} else {
				fmt.Print(".")
			}
		}
	}()

	// send packets on the main goroutine
	for {
		for _, peer := range peers {
			copy(payload[32:64], peer.Pubkey[:])

			packet := MakePacket(payload, server, client)
			_, err := rawConn.WriteToIP(packet, server.Addr)
			if err != nil {
				log.Println("\nError sending packet:", err)
				continue
			}
		}
	}
}

func parseForBPF(response []byte) (srcIP net.IP, srcPort uint16, dstPort uint16) {
	srcIP = make([]byte, 4)
	srcIPBytes := bytes.NewBuffer(response[12:16])
	srcPortBytes := bytes.NewBuffer(response[20:22])
	dstPortBytes := bytes.NewBuffer(response[22:24])

	binary.Read(srcIPBytes, binary.BigEndian, &srcIP)
	binary.Read(srcPortBytes, binary.BigEndian, &srcPort)
	binary.Read(dstPortBytes, binary.BigEndian, &dstPort)
	return
}
