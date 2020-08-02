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

// 28 = ip header + udp header
const emptyUDPsize = 28

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr,
			"Usage:", os.Args[0], "SERVER:PORT WIREGUARD_INTERFACE\n"+
				"Example:\n"+
				"   ", os.Args[0], "demo.wireguard.com:12345 wg0")
		os.Exit(1)
	}

	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "Must be root!")
		os.Exit(1)
	}

	serverSplit := strings.Split(os.Args[1], ":")
	serverHostnameStr := serverSplit[0]
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, "Please include a port like this:", serverHostnameStr+":PORT")
		os.Exit(1)
	}
	serverPort, err := strconv.Atoi(serverSplit[1])
	if err != nil {
		log.Fatalln("Error parsing server port:", err)
	}
	iface := os.Args[2]

	serverAddr := hostToAddr(serverHostnameStr)
	clientIP := getClientIP(serverAddr.IP)

	clientPort := getClientPort(iface)
	clientPubkey := getClientPubkey(iface)

	runCmd("wg-quick", "up", iface)
	peerKeysStr := getPeers(iface)
	pubkeyMap := makeKeyMap(peerKeysStr)

	rawConn := setupRawConn(serverAddr, serverPort, clientIP, clientPort)

	payload := make([]byte, 64)
	copy(payload[0:32], clientPubkey[:])

	response := make([]byte, 4096)

	keepRequesting := true
	for keepRequesting {
		keepRequesting = false
		for peerPubkey, resolved := range pubkeyMap {
			if resolved {
				continue
			}
			fmt.Print("[+] Requesting peer " + base64.RawStdEncoding.EncodeToString(peerPubkey[:]) + ": ")
			copy(payload[32:64], peerPubkey[:])

			packet := makePacket(payload, serverAddr.IP, serverPort, clientIP, clientPort)
			_, err := rawConn.WriteToIP(packet, serverAddr)
			if err != nil {
				log.Println("Error sending packet:", err)
				continue
			}

			rawConn.SetReadDeadline(time.Now().Add(timeout))
			n, err := rawConn.Read(response)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					fmt.Println("\nConnection to", serverHostnameStr, "timed out.")
					continue
				}
				fmt.Println("\nError receiving packet:", err)
				continue
			}

			if n == emptyUDPsize {
				fmt.Println("Server doesn't have it yet")
				keepRequesting = true
				continue
			} else if n < emptyUDPsize {
				log.Println("\nError: not a valid udp packet")
				continue
			}

			// fmt.Println(n, "bytes read")

			ip, port := parseResponse(response)

			fmt.Println(ip.String() + ":" + strconv.Itoa(port))
			setPeer(peerPubkey, ip, port, iface)

			pubkeyMap[peerPubkey] = true
		}
		if keepRequesting {
			time.Sleep(time.Second * 2)
		}
	}
	fmt.Println("Closing socket...")
	rawConn.Close()
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

func setupRawConn(serverAddr *net.IPAddr, serverPort int, clientIP net.IP, clientPort int) *ipv4.RawConn {
	packetConn, err := net.ListenPacket("ip4:udp", clientIP.String())
	if err != nil {
		log.Fatalln("Error creating packetConn", err)
	}

	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Fatalln("Error creating rawConn", err)
	}

	applyBPF(rawConn, serverAddr.IP, uint32(serverPort), uint32(clientPort))

	return rawConn
}

func applyBPF(rawConn *ipv4.RawConn, serverIP net.IP, serverPort, clientPort uint32) {
	ipArr := []byte(serverIP.To4())
	ipInt := uint32(ipArr[0])<<(3*8) + uint32(ipArr[1])<<(2*8) + uint32(ipArr[2])<<8 + uint32(ipArr[3])

	// fmt.Println("IP as an int:", ipInt)

	bpfRaw, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 4}, //src ip
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipInt, SkipFalse: 0, SkipTrue: 5},
		bpf.LoadAbsolute{Off: 20, Size: 2}, //src port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: serverPort, SkipFalse: 0, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 22, Size: 2}, //dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: clientPort, SkipFalse: 0, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 1<<(8*4) - 1}, // max uint32 size (entire packet)
	})

	err = rawConn.SetBPF(bpfRaw)
	if err != nil {
		log.Fatalln("Error setting bpf", err)
	}
}

func makePacket(payload []byte, serverIP net.IP, serverPort int, clientIP net.IP, clientPort int) []byte {
	buf := gopacket.NewSerializeBuffer()

	// this does the hard stuff for us
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipHeader := layers.IPv4{
		SrcIP:    clientIP,
		DstIP:    serverIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udpHeader := layers.UDP{
		SrcPort: layers.UDPPort(clientPort),
		DstPort: layers.UDPPort(serverPort),
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

func getClientPort(iface string) int {
	output, err := runCmd("wg", "show", iface, "listen-port")
	if err != nil {
		log.Fatalln("Error getting listen port:", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		log.Fatalln("Error parsing listen port:", err)
	}
	return port
}

func getPeers(iface string) []string {
	output, err := runCmd("wg", "show", iface, "peers")
	if err != nil {
		log.Fatalln("Error getting peers", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n")
}

func getClientPubkey(iface string) [32]byte {
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
	return keyArr
}

func makeKeyMap(peerKeys []string) map[[32]byte]bool {
	keyMap := make(map[[32]byte]bool)
	for _, key := range peerKeys {
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			log.Fatalln("Error decoding key "+key+":", err)
		}
		keyArr := [32]byte{}
		copy(keyArr[:], keyBytes)

		keyMap[keyArr] = false
	}
	return keyMap
}

func parseResponse(response []byte) (net.IP, int) {
	var ip net.IP
	var ipv4Slice []byte = make([]byte, 4)
	var port uint16
	packet := gopacket.NewPacket(response, layers.LayerTypeIPv4, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	payload := packet.ApplicationLayer().LayerContents()

	data := bytes.NewBuffer(payload)
	// fmt.Println("Layer payload:\n", hex.Dump(data.Bytes()))

	binary.Read(data, binary.BigEndian, &ipv4Slice)
	ip = net.IP(ipv4Slice)
	binary.Read(data, binary.BigEndian, &port)
	// fmt.Println("ip:", ip.String(), "port:", port)
	return ip, int(port)
}

func setPeer(pubkey [32]byte, ip net.IP, port int, iface string) {
	keyString := base64.StdEncoding.EncodeToString(pubkey[:])
	runCmd("wg",
		"set", iface,
		"peer", keyString,
		"persistent-keepalive", persistentKeepalive,
		"endpoint", ip.String()+":"+strconv.Itoa(port),
	)
}
