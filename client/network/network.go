package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const udpProtocol = 17

// 28 = ip header + udp header
const EmptyUDPsize = 28

// Pubkey stores a 32 byte representation of a Wireguard public key
type Pubkey [32]byte

// Server stores data relating to the server and its location
type Server struct {
	Hostname string
	Addr     *net.IPAddr
	Port     uint16
}

// Peer stores data about a peer's key and endpoint, whether it's another peer or the client
// we use resolved to check if a peer's ip and port have been filled in.
// this seems clearer than checking if port == 0
type Peer struct {
	Resolved bool
	IP       net.IP
	Port     uint16
	Pubkey   Pubkey
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

func GetClientIP(dstIP net.IP) net.IP {
	// i wanted to use gopacket/routing but it breaks when the vpn iface is already up
	routes, err := netlink.RouteGet(dstIP)
	if err != nil {
		log.Fatalln("Error getting route:", err)
	}
	// pick the first one cuz why not
	return routes[0].Src
}

func HostToAddr(hostStr string) *net.IPAddr {
	remoteAddrs, err := net.LookupHost(hostStr)
	if err != nil {
		log.Fatalln("Error parsing remote address", err)
	}

	for _, addrStr := range remoteAddrs {
		if remoteAddr, err := net.ResolveIPAddr("ip4", addrStr); err == nil {
			return remoteAddr
		}
	}
	return nil
}

func SetupRawConn(server *Server, client *Peer) *ipv4.RawConn {
	packetConn, err := net.ListenPacket("ip4:udp", client.IP.String())
	if err != nil {
		log.Fatalln("Error creating packetConn", err)
	}

	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Fatalln("Error creating rawConn", err)
	}

	ApplyBPF(rawConn, server, client)

	return rawConn
}

func ApplyBPF(rawConn *ipv4.RawConn, server *Server, client *Peer) {
	const ipv4HeaderLen = 20

	const srcIPOffset = 12
	const srcPortOffset = ipv4HeaderLen + 0
	const dstPortOffset = ipv4HeaderLen + 2

	ipArr := []byte(server.Addr.IP.To4())
	ipInt := uint32(ipArr[0])<<(3*8) + uint32(ipArr[1])<<(2*8) + uint32(ipArr[2])<<8 + uint32(ipArr[3])

	fmt.Println("IP as an int:", ipInt)

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
		log.Fatalln("Error setting bpf", err)
	}
}

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

// there's no error checking, we assume that data passed in is valid
func ParseResponse(response []byte) (net.IP, uint16) {
	var ip net.IP
	var ipv4Slice []byte = make([]byte, 4)
	var port uint16
	packet := gopacket.NewPacket(response, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	if packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
		return nil, 0
	}
	payload := packet.ApplicationLayer().LayerContents()

	data := bytes.NewBuffer(payload)
	// fmt.Println("Layer payload:\n", hex.Dump(data.Bytes()))

	binary.Read(data, binary.BigEndian, &ipv4Slice)
	ip = net.IP(ipv4Slice)
	binary.Read(data, binary.BigEndian, &port)
	// fmt.Println("ip:", ip.String(), "port:", port)
	return ip, port
}
