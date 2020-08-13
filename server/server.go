package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
)

// Endpoint is the location of a peer.
type Endpoint struct {
	ip   net.IP
	port uint16
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "PORT")
		os.Exit(1)
	}

	port := os.Args[1]

	fmt.Println("Starting nat-punching server on port", port)
	peers := make(map[[32]byte]Endpoint)

	// the client can only handle IPv4 addresses right now.
	listenAddr, err := net.ResolveUDPAddr("udp4", ":"+port)
	if err != nil {
		log.Panicln("Error getting UDP address", err)
	}

	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		log.Panicln("Error getting UDP listen connection")
	}

	for {
		err := handleConnection(conn, peers)
		if err != nil {
			log.Panicln("Error handling the connection", err)
		}
	}
}

func handleConnection(conn *net.UDPConn, peers map[[32]byte]Endpoint) error {
	var packet [64]byte

	_, clientAddr, err := conn.ReadFromUDP(packet[:])
	if err != nil {
		return err
	}

	var clientPubKey [32]byte
	copy(clientPubKey[:], packet[0:32])

	var targetPubKey [32]byte
	copy(targetPubKey[:], packet[32:64])

	clientLocation := Endpoint{
		ip:   clientAddr.IP,
		port: uint16(clientAddr.Port),
	}

	peers[clientPubKey] = clientLocation

	targetLocation, exists := peers[targetPubKey]

	response := bytes.NewBuffer([]byte{})

	if exists {
		binary.Write(response, binary.BigEndian, targetLocation.ip)
		binary.Write(response, binary.BigEndian, targetLocation.port)
	}
	// otherwise send an empty response

	_, err = conn.WriteToUDP(response.Bytes(), clientAddr)
	if err != nil {
		return nil
	}

	fmt.Print(
		base64.StdEncoding.EncodeToString(clientPubKey[:])[:16],
		" ==> ",
		base64.StdEncoding.EncodeToString(targetPubKey[:])[:16],
		": ",
	)

	if exists {
		fmt.Println("CONNECTED")
	} else {
		fmt.Println("NOT FOUND")
	}

	return nil
}
