package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ogier/pflag"

	"github.com/malcolmseyd/natpunch-go/client/cmd"
	"github.com/malcolmseyd/natpunch-go/client/network"
	"github.com/malcolmseyd/natpunch-go/client/util"
)

const timeout = time.Second * 10
const persistentKeepalive = 25

func main() {
	pflag.Usage = printUsage

	continuous := pflag.BoolP("continuous", "c", false, "continuously resolve peers after they've already been resolved")
	delay := pflag.Float32P("delay", "d", 2.0, "time to wait between retries (in seconds)")

	pflag.Parse()
	args := pflag.Args()

	if len(args) < 3 {
		printUsage()
		os.Exit(1)
	}

	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "Must be root!")
		os.Exit(1)
	}

	ifaceName := args[0]

	serverSplit := strings.Split(args[1], ":")
	serverHostname := serverSplit[0]
	if len(serverSplit) < 2 {
		fmt.Fprintln(os.Stderr, "Please include a port like this:", serverHostname+":PORT")
		os.Exit(1)
	}

	serverAddr := network.HostToAddr(serverHostname)

	serverPort, err := strconv.ParseUint(serverSplit[1], 10, 16)
	if err != nil {
		log.Fatalln("Error parsing server port:", err)
	}

	serverKey, err := base64.StdEncoding.DecodeString(args[2])
	if err != nil || len(serverKey) != 32 {
		log.Fatalln("Server key has improper formatting")
	}
	var serverKeyArr network.Key
	copy(serverKeyArr[:], serverKey)

	server := network.Server{
		Hostname: serverHostname,
		Addr:     serverAddr,
		Port:     uint16(serverPort),
		Pubkey:   serverKeyArr,
	}

	run(ifaceName, server, *continuous, *delay)
}

func run(ifaceName string, server network.Server, continuous bool, delay float32) {
	// get the source ip that we'll send the packet from
	clientIP := network.GetClientIP(server.Addr.IP)

	cmd.RunCmd("wg-quick", "up", ifaceName)

	// get info about the Wireguard config
	clientPort := cmd.GetClientPort(ifaceName)
	clientPubkey := cmd.GetClientPubkey(ifaceName)
	clientPrivkey := cmd.GetClientPrivkey(ifaceName)

	client := network.Peer{
		IP:     clientIP,
		Port:   clientPort,
		Pubkey: clientPubkey,
	}

	peerKeysStr := cmd.GetPeers(ifaceName)
	var peers []network.Peer = util.MakePeerSlice(peerKeysStr)

	// we're using raw sockets to spoof the source port,
	// which is already being used by Wireguard
	rawConn := network.SetupRawConn(&server, &client)
	defer rawConn.Close()

	// payload consists of client key + peer key
	payload := make([]byte, 64)
	copy(payload[0:32], clientPubkey[:])

	totalPeers := len(peers)
	resolvedPeers := 0

	fmt.Println("Resolving", totalPeers, "peers")

	// Noise handshake
	sendCipher, recvCipher, index, err := network.Handshake(rawConn, timeout, clientPrivkey, &server, &client)
	if err != nil {
		log.Fatalln("Handshake failed:", err)
	}

	// we keep requesting if the server doesn't have one of our peers.
	// this keeps running until all connections are established.
	tryAgain := true
	for tryAgain {
		tryAgain = false
		for i, peer := range peers {
			if peer.Resolved && !continuous {
				continue
			}
			fmt.Printf("(%d/%d) %s: ", resolvedPeers, totalPeers, base64.RawStdEncoding.EncodeToString(peer.Pubkey[:])[:16])
			copy(payload[32:64], peer.Pubkey[:])

			err := network.SendDataPacket(sendCipher, index, payload, rawConn, &server, &client)
			if err != nil {
				log.Println("\nError sending packet:", err)
				continue
			}

			// throw away udp header, we have no use for it right now
			body, _, packetType, n, err := network.RecvDataPacket(recvCipher, rawConn, timeout, &server, &client)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					fmt.Println("\nConnection to", server.Hostname, "timed out.")
					tryAgain = true
					continue
				}
				fmt.Println("\nError receiving packet:", err)
				continue
			}
			if packetType != network.PacketData {
				fmt.Println("\nExpected data packet, got", packetType)
			}

			if len(body) == 0 {
				fmt.Println("not found")
				tryAgain = true
				continue
			} else if len(body) != 4+2 {
				// expected packet size, 4 bytes for ip, 2 for port
				log.Println("\nError: invalid response of length", len(body))
				// For debugging
				fmt.Println(hex.Dump(body[:n]))
				tryAgain = true
				continue
			}

			peer.IP, peer.Port = network.ParseResponse(body)
			if peer.IP == nil {
				log.Println("Error parsing packet: not a valid UDP packet")
			}
			if !peer.Resolved {
				peer.Resolved = true
				resolvedPeers++
			}

			fmt.Println(peer.IP.String() + ":" + strconv.FormatUint(uint64(peer.Port), 10))
			cmd.SetPeer(&peer, persistentKeepalive, ifaceName)

			peers[i] = peer

			if continuous {
				// always try again if continuous
				tryAgain = true
			}
		}
		if tryAgain {
			time.Sleep(time.Second * time.Duration(delay))
		}
	}
	fmt.Print("Resolved ", resolvedPeers, " peer")
	if totalPeers != 1 {
		fmt.Print("s")
	}
	fmt.Print("\n")
}

func printUsage() {
	fmt.Fprintf(os.Stderr,
		"Usage: %s [OPTION]... WIREGUARD_INTERFACE SERVER_HOSTNAME:PORT SERVER_PUBKEY\n"+
			"Flags:\n", os.Args[0],
	)
	pflag.PrintDefaults()
	fmt.Fprintf(os.Stderr,
		"Example:\n"+
			"    %s wg0 demo.wireguard.com:12345 1rwvlEQkF6vL4jA1gRzlTM7I3tuZHtdq8qkLMwBs8Uw=\n",
		os.Args[0],
	)
}
