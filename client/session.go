package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/malcolmseyd/natpunch-go/client/network"
	"github.com/malcolmseyd/natpunch-go/client/util"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

type Session struct {
	cfg    Config
	client network.Client
	server network.Server
	conn   *network.Conn
	peers  []network.Peer
}

// TODO break up this GARGANTUAN function
func (s *Session) Run() {
	var err error

	s.Init()
	defer func() {
		err := s.Stop()
		if err != nil {
			util.Eprintln("Error stopping session:", err)
		}
	}()

	// payload consists of client key + peer key
	payload := make([]byte, 64)
	copy(payload[0:32], s.client.Pubkey[:])

	totalPeers := len(s.peers)
	resolvedPeers := 0

	// TODO function for the main loop
	fmt.Println("Resolving", totalPeers, "peers")

	// we keep requesting if the server doesn't have one of our peers.
	// this keeps running until all connections are established.
	tryAgain := true
	for tryAgain {
		tryAgain = false
		for i, peer := range s.peers {
			if peer.Resolved && !s.cfg.continuous {
				continue
			}
			// Noise handshake w/ key rotation
			if time.Since(s.server.LastHandshake) > network.RekeyDuration {
				err = s.conn.Handshake()
				if err != nil {
					if err, ok := err.(net.Error); ok && err.Timeout() {
						fmt.Println("Connection to", s.server.Hostname, "timed out.")
						tryAgain = true
						break
					}
					util.Eprintln(os.Stderr, "Key rotation failed:", err)
					tryAgain = true
					break
				}
			}
			fmt.Printf("(%d/%d) %s: ", resolvedPeers, totalPeers, base64.RawStdEncoding.EncodeToString(peer.Pubkey[:])[:16])
			copy(payload[32:64], peer.Pubkey[:])

			// TODO function for network stuff
			//err := network.SendDataPacket(sendCipher, index, payload, rawConn, server, client)
			err := s.conn.SendData(payload)
			if err != nil {
				log.Println("\nError sending packet:", err)
				continue
			}

			//response, _, packetType, n, err := network.RecvDataPacket(recvCipher, rawConn)
			response, packetType, n, err := s.conn.RecvData()
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					fmt.Println("\nConnection to", s.server.Hostname, "timed out.")
					tryAgain = true
					continue
				}
				fmt.Println("\nError receiving packet:", err)
				continue
			}
			// TODO function for packet parsing
			if packetType != network.PacketData {
				fmt.Println("\nExpected data packet, got", packetType)
			}

			if len(response) == 0 {
				fmt.Println("not found")
				tryAgain = true
				continue
			} else if len(response) != 4+2 {
				// expected packet size, 4 bytes for ip, 2 for port
				log.Println("\nError: invalid response of length", len(response))
				// For debugging
				fmt.Println(hex.Dump(response[:n]))
				tryAgain = true
				continue
			}

			peer.IP, peer.Port = network.ParseEndpoint(response)
			if peer.IP == nil {
				log.Println("Error parsing packet: not a valid UDP packet")
			}
			if !peer.Resolved {
				peer.Resolved = true
				resolvedPeers++
			}

			fmt.Println(peer.IP.String() + ":" + strconv.FormatUint(uint64(peer.Port), 10))
			err = network.UpdatePeer(&peer, persistentKeepalive, s.cfg.ifaceName)
			if err != nil {
				fmt.Println("Error updating peer:", err)
			}

			s.peers[i] = peer

			if s.cfg.continuous {
				// always try again if continuous
				tryAgain = true
			}
		}
		if tryAgain {
			time.Sleep(time.Nanosecond * time.Duration(s.cfg.delay*1e9))
		}
	}
	fmt.Print("Resolved ", resolvedPeers, " peer")
	if totalPeers != 1 {
		fmt.Print("s")
	}
	fmt.Print("\n")
}

// Init sets up the initial state for Session.
func (s *Session) Init() {
	var err error
	// Since every error in this function is fatal, no return value is required.
	s.client, err = network.NewClient(s.cfg.ifaceName, &s.server)
	if err == network.ErrIfaceDown {
		err = network.SetIfaceUp(s.cfg.ifaceName)
	}
	if err != nil {
		util.Eprintln("Error getting client info:", err)
		os.Exit(1)
	}

	s.peers, err = network.GetPeers(s.cfg.ifaceName)
	if err != nil {
		util.Eprintln("Error getting peers:", err)
		os.Exit(1)
	}

	// we're using raw sockets to spoof the source port,
	// which is already being used by Wireguard
	s.conn = network.NewConn(&s.server, &s.client)
}

func (s *Session) Stop() (err error) {
	err = s.conn.Close()
	if err != nil {
		return err
	}
	return
}
