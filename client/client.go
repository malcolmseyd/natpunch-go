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

	"github.com/malcolmseyd/natpunch-go/client/cmd"
	"github.com/malcolmseyd/natpunch-go/client/network"
	"github.com/malcolmseyd/natpunch-go/client/util"
)

const timeout = time.Second * 10
const persistentKeepalive = "25"

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

	serverAddr := network.HostToAddr(serverHostname)

	serverPort, err := strconv.ParseUint(serverSplit[1], 10, 16)
	if err != nil {
		log.Fatalln("Error parsing server port:", err)
	}
	server := network.Server{
		Hostname: serverHostname,
		Addr:     serverAddr,
		Port:     uint16(serverPort),
	}
	ifaceName := os.Args[2]

	run(ifaceName, server)
}

func run(ifaceName string, server network.Server) {
	// get the source ip that we'll send the packet from
	clientIP := network.GetClientIP(server.Addr.IP)

	cmd.RunCmd("wg-quick", "up", ifaceName)

	// get info about the Wireguard config
	clientPort := cmd.GetClientPort(ifaceName)
	clientPubkey := cmd.GetClientPubkey(ifaceName)

	client := network.Peer{
		IP:     clientIP,
		Port:   clientPort,
		Pubkey: clientPubkey,
	}

	peerKeysStr := cmd.GetPeers(ifaceName)
	var peers []network.Peer = util.MakePeerSlice(peerKeysStr)

	// we're using raw sockets to spoof the source IP
	rawConn := network.SetupRawConn(&server, &client)

	// payload consists of client key + peer key
	payload := make([]byte, 64)
	copy(payload[0:32], clientPubkey[:])

	response := make([]byte, 4096)

	fmt.Println("Resolving", len(peers), "peers")

	// we keep requesting if the server doesn't have one of our peers.
	// this could run in the background until all connections are established.

	keepRequesting := true
	for keepRequesting {
		keepRequesting = false
		for i, peer := range peers {
			if peer.Resolved {
				continue
			}
			fmt.Print("[+] Requesting peer " + base64.RawStdEncoding.EncodeToString(peer.Pubkey[:]) + ": ")
			copy(payload[32:64], peer.Pubkey[:])

			packet := network.MakePacket(payload, &server, &client)
			_, err := rawConn.WriteToIP(packet, server.Addr)
			if err != nil {
				log.Println("\nError sending packet:", err)
				continue
			}

			rawConn.SetReadDeadline(time.Now().Add(timeout))
			n, err := rawConn.Read(response)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					fmt.Println("\nConnection to", server.Hostname, "timed out.")
					continue
				}
				fmt.Println("\nError receiving packet:", err)
				continue
			}

			if n == network.EmptyUDPsize {
				fmt.Println("not found")
				keepRequesting = true
				continue
			} else if n < network.EmptyUDPsize {
				log.Println("\nError: response is not a valid udp packet")
				continue
			} else if n != network.EmptyUDPsize+4+2 {
				// expected packet size, 4 bytes for ip, 2 for port
				log.Println("\nError: invalid response of length", n)
				// For debugging
				fmt.Println(hex.Dump(response[:n]))
				keepRequesting = true
				continue
			}

			peer.IP, peer.Port = network.ParseResponse(response)
			if peer.IP == nil {
				log.Println("Error: packet was not UDP")
			}
			peer.Resolved = true

			fmt.Println(peer.IP.String() + ":" + strconv.FormatUint(uint64(peer.Port), 10))
			cmd.SetPeer(&peer, persistentKeepalive, ifaceName)

			peers[i] = peer
		}
		if keepRequesting {
			time.Sleep(time.Second * 2)
		}
	}
	fmt.Println("Closing socket...")
	rawConn.Close()
}
