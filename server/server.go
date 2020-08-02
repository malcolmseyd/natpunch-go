package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
)

type peerLocation struct {
	ip   net.IP
	port uint16
}

const defaultPort = 12404

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "PORT")
		os.Exit(1)
	}

	fmt.Println("Starting nat-punching server.")
	peers := make(map[[32]byte]peerLocation)

	// the client can only handle IPv4 addresses right now.
	listenAddr, err := net.ResolveUDPAddr("udp4", ":"+strconv.Itoa(defaultPort))
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

func handleConnection(conn *net.UDPConn, peers map[[32]byte]peerLocation) error {
	var packet [64]byte

	_, clientAddr, err := conn.ReadFromUDP(packet[:])
	if err != nil {
		return err
	}

	var clientPubKey [32]byte
	copy(clientPubKey[:], packet[0:32])

	var targetPubKey [32]byte
	copy(targetPubKey[:], packet[32:64])

	clientLocation := peerLocation{
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

	if exists {
		fmt.Println(
			"Connected", base64.StdEncoding.EncodeToString(clientPubKey[:]),
			"at", clientAddr.String(),
			"to", base64.StdEncoding.EncodeToString(targetPubKey[:]),
			"at", targetLocation.ip.String()+":"+strconv.Itoa(int(targetLocation.port)),
		)
	} else {
		fmt.Println(
			base64.StdEncoding.EncodeToString(clientPubKey[:]),
			"at", clientAddr.String(),
			"requested", base64.StdEncoding.EncodeToString(targetPubKey[:]),
			"but it could not be found.",
		)
	}

	return nil
}
