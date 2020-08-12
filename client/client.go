package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const timeout = time.Second * 10
const persistentKeepalive = "25"

const udpProtocol = 17

// 28 = ip header + udp header
const emptyUDPsize = 28

// Pubkey stores a 32 byte representation of a Wireguard public key
type Pubkey [32]byte

// Server stores data relating to the server and its location
type Server struct {
	hostname string
	addr     *net.IPAddr
	port     uint16
}

// Peer stores data about a peer's key and endpoint, whether it's another peer or the client
// we use resolved to check if a peer's ip and port have been filled in.
// this seems clearer than checking if port == 0
type Peer struct {
	resolved bool
	ip       net.IP
	port     uint16
	pubkey   Pubkey
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr,
			"Usage:", os.Args[0], "SERVER_HOSTNAME:PORT WIREGUARD_INTERFACE\n"+
				"Example:\n"+
				"   ", os.Args[0], "demo.wireguard.com:12345 wg0")
		os.Exit(1)
	}

	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "Must be root!")
		os.Exit(1)
	}

	serverSplit := strings.Split(os.Args[1], ":")
	serverHostname := serverSplit[0]
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, "Please include a port like this:", serverHostname+":PORT")
		os.Exit(1)
	}

	serverAddr := hostToAddr(serverHostname)

	serverPort, err := strconv.ParseUint(serverSplit[1], 10, 16)
	if err != nil {
		log.Fatalln("Error parsing server port:", err)
	}
	server := Server{
		hostname: serverHostname,
		addr:     serverAddr,
		port:     uint16(serverPort),
	}
	ifaceName := os.Args[2]

	run(ifaceName, server)
}

func run(ifaceName string, server Server) {
	// get the source ip that we'll send the packet from
	clientIP := getClientIP(server.addr.IP)

	runCmd("wg-quick", "up", ifaceName)

	// get info about the Wireguard config
	clientPort := getClientPort(ifaceName)
	clientPubkey := getClientPubkey(ifaceName)

	client := Peer{
		ip:     clientIP,
		port:   clientPort,
		pubkey: clientPubkey,
	}

	peerKeysStr := getPeers(ifaceName)
	var peers []Peer = makePeerSlice(peerKeysStr)

	// we're using raw sockets to spoof the source IP
	rawConn := setupRawConn(&server, &client)

	// payload consists of client key + peer key
	payload := make([]byte, 64)
	copy(payload[0:32], clientPubkey[:])

	response := make([]byte, 4096)

	// fmt.Println("Resolving", len(peers), "peers")

	// we keep requesting if the server doesn't have one of our peers.
	// this could run in the background until all connections are established.
	go func() {
		for {
			n, err := rawConn.Read(response)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					fmt.Println("\nConnection to", server.hostname, "timed out.")
					continue
				}
				fmt.Println("\nError receiving packet:", err)
				continue
			}
			// fmt.Println(n-28, "bytes read")
			if n != 28 && n != 28+6 {
				srcIP, srcPort, dstPort := parseForBPF(response)
				fmt.Println("\nInvalid response of", n, "bytes")
				fmt.Println("SRC IP:", srcIP, "EXPECTED", server.addr.IP)
				fmt.Println("SRC PORT:", srcPort, "EXPECTED", server.port)
				fmt.Println("DST PORT:", dstPort, "EXPECTED", client.port)
				fmt.Println()
				// fmt.Println(hex.Dump(response[:n]))
			} else {
				fmt.Print(".")
			}
		}
	}()
	keepRequesting := true
	for keepRequesting {
		keepRequesting = false
		// for i, peer := range peers {
		for _, peer := range peers {
			if peer.resolved {
				continue
			}
			// fmt.Print("[+] Requesting peer " + base64.RawStdEncoding.EncodeToString(peer.pubkey[:]) + ": ")
			copy(payload[32:64], peer.pubkey[:])

			packet := makePacket(payload, &server, &client)
			_, err := rawConn.WriteToIP(packet, server.addr)
			if err != nil {
				log.Println("\nError sending packet:", err)
				continue
			}

			// rawConn.SetReadDeadline(time.Now().Add(timeout))
			// n, err := rawConn.Read(response)
			// if err != nil {
			// 	if err, ok := err.(net.Error); ok && err.Timeout() {
			// 		fmt.Println("\nConnection to", server.hostname, "timed out.")
			// 		continue
			// 	}
			// 	fmt.Println("\nError receiving packet:", err)
			// 	continue
			// }

			// For debugging BPF
			// fmt.Println(hex.Dump(response[:n]))
			keepRequesting = true
			continue

			// if n == emptyUDPsize {
			// 	fmt.Println("not found")
			// 	keepRequesting = true
			// 	continue
			// } else if n < emptyUDPsize {
			// 	log.Println("\nError: response is not a valid udp packet")
			// 	continue
			// } else if n != emptyUDPsize+4+2 {
			// 	// expected packet size, 4 bytes for ip, 2 for port
			// 	log.Println("\nError: invalid response of length", n)
			// 	// For debugging
			// 	fmt.Println(hex.Dump(response[:n]))
			// 	keepRequesting = true
			// 	continue
			// }

			// peer.ip, peer.port = parseResponse(response)
			// if peer.ip == nil {
			// 	log.Println("Error: packet was not UDP")
			// }
			// peer.resolved = true

			// fmt.Println(peer.ip.String() + ":" + strconv.FormatUint(uint64(peer.port), 10))
			// setPeer(&peer, ifaceName)

			// peers[i] = peer
		}
		if keepRequesting {
			time.Sleep(time.Second * 2)
		}
	}
	fmt.Println("Closing socket...")
	rawConn.Close()
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

func getClientIP(dstIP net.IP) net.IP {
	// i wanted to use gopacket/routing but it breaks when the vpn iface is already up
	routes, err := netlink.RouteGet(dstIP)
	if err != nil {
		log.Fatalln("Error getting route:", err)
	}
	// pick the first one cuz why not
	return routes[0].Src
}

func hostToAddr(hostStr string) *net.IPAddr {
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

func setupRawConn(server *Server, client *Peer) *ipv4.RawConn {
	packetConn, err := net.ListenPacket("ip4:udp", client.ip.String())
	if err != nil {
		log.Fatalln("Error creating packetConn", err)
	}

	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Fatalln("Error creating rawConn", err)
	}

	applyBPF(rawConn, server, client)

	return rawConn
}

func applyBPF(rawConn *ipv4.RawConn, server *Server, client *Peer) {

	// WHAT WE KNOW
	// - Filtering with just one jump works :)
	//   - This applies to all options (src/dst port, src ip)

	// WHAT WE WILL RESEARCH
	// Can we chain the options by changing the numbers?

	const ipv4HeaderLen = 20

	const srcIPOffset = 12
	const srcPortOffset = ipv4HeaderLen + 0
	const dstPortOffset = ipv4HeaderLen + 2

	ipArr := []byte(server.addr.IP.To4())
	ipInt := uint32(ipArr[0])<<(3*8) + uint32(ipArr[1])<<(2*8) + uint32(ipArr[2])<<8 + uint32(ipArr[3])

	fmt.Println("IP as an int:", ipInt)

	// we don't need to filter packet type because the rawconn is ipv4-udp only
	// Skip values represent the number of instructions to skip if true or false
	// We can skip to the end if we get a !=, otherwise keep going
	bpfRaw, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: srcIPOffset, Size: 4}, //src ip is server
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipInt, SkipFalse: 5, SkipTrue: 0},

		bpf.LoadAbsolute{Off: srcPortOffset, Size: 2}, //src port is server
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(server.port), SkipFalse: 3, SkipTrue: 0},

		bpf.LoadAbsolute{Off: dstPortOffset, Size: 2}, //dst port is client
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(client.port), SkipFalse: 1, SkipTrue: 0},

		bpf.RetConstant{Val: 1<<(8*4) - 1}, // max number that fits this value (entire packet)
		bpf.RetConstant{Val: 0},
	})

	err = rawConn.SetBPF(bpfRaw)
	if err != nil {
		log.Fatalln("Error setting bpf", err)
	}
}

func makePacket(payload []byte, server *Server, client *Peer) []byte {
	buf := gopacket.NewSerializeBuffer()

	// this does the hard stuff for us
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipHeader := layers.IPv4{
		SrcIP:    client.ip,
		DstIP:    server.addr.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udpHeader := layers.UDP{
		SrcPort: layers.UDPPort(client.port),
		DstPort: layers.UDPPort(server.port),
	}

	payloadLayer := gopacket.Payload(payload)

	udpHeader.SetNetworkLayerForChecksum(&ipHeader)

	gopacket.SerializeLayers(buf, opts, &ipHeader, &udpHeader, &payloadLayer)

	return buf.Bytes()
}

func runCmd(command string, args ...string) (string, error) {
	outBytes, err := exec.Command(command, args...).Output()
	if err != nil {
		return "", err
	}
	return string(outBytes), nil
}

func getClientPort(iface string) uint16 {
	output, err := runCmd("wg", "show", iface, "listen-port")
	if err != nil {
		log.Fatalln("Error getting listen port:", err)
	}
	// guaranteed castable to uint16
	port, err := strconv.ParseUint(strings.TrimSpace(output), 10, 16)
	if err != nil {
		log.Fatalln("Error parsing listen port:", err)
	}
	return uint16(port)
}

func getPeers(iface string) []string {
	output, err := runCmd("wg", "show", iface, "peers")
	if err != nil {
		log.Fatalln("Error getting peers", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n")
}

func getClientPubkey(iface string) Pubkey {
	var keyArr [32]byte
	output, err := runCmd("wg", "show", iface, "public-key")
	if err != nil {
		log.Fatalln("Error getting client pubkey:", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing client pubkey")
	}
	copy(keyArr[:], keyBytes)
	return Pubkey(keyArr)
}

func makePeerSlice(peerKeys []string) []Peer {
	keys := make([]Peer, len(peerKeys))
	for i, key := range peerKeys {
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Fatalln("Error decoding key "+key+":", err)
		}
		keyArr := [32]byte{}
		copy(keyArr[:], keyBytes)
		// all other fields initialize to zero values
		peer := Peer{
			pubkey:   Pubkey(keyArr),
			resolved: false,
		}
		keys[i] = peer
	}
	return keys
}

// there's no error checking, we assume that data passed in is valid
func parseResponse(response []byte) (net.IP, uint16) {
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

func setPeer(peer *Peer, iface string) {
	keyString := base64.StdEncoding.EncodeToString(peer.pubkey[:])
	runCmd("wg",
		"set", iface,
		"peer", keyString,
		"persistent-keepalive", persistentKeepalive,
		"endpoint", peer.ip.String()+":"+strconv.FormatUint(uint64(peer.port), 10),
	)
}
