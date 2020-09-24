package main

import (
	"encoding/base64"
	"github.com/malcolmseyd/natpunch-go/client/network"
	"github.com/malcolmseyd/natpunch-go/client/util"
	"github.com/ogier/pflag"
	"os"
	"strconv"
	"strings"
)

// Config stores values related to program configuration
type Config struct {
	continuous bool
	delay      float64

	ifaceName string
	hostname  string
	port      uint16
	key       network.Key
}

func newConfig() Config {
	var err error
	config := Config{}

	pflag.Usage = printUsage

	continuous := pflag.BoolP("continuous", "c", false, "continuously resolve peers after they've already been resolved")
	delay := pflag.Float64P("delay", "d", 2.0, "time to wait between retries (in seconds)")

	pflag.Parse()
	config.continuous = *continuous
	config.delay = *delay

	args := pflag.Args()

	if len(args) < 3 {
		util.Eprintln("Too few arguments")
		printUsage()
		os.Exit(1)
	}

	if os.Getuid() != 0 {
		util.Eprintln("Must be root!")
		os.Exit(1)
	}

	config.ifaceName = args[0]

	serverSplit := strings.Split(args[1], ":")
	config.hostname = serverSplit[0]
	if len(serverSplit) < 2 {
		util.Eprintln("Please include a port like this:", config.hostname+":PORT")
		os.Exit(1)
	}

	// ParseUint can be safely cast to uint16 because of the last argument
	port, err := strconv.ParseUint(serverSplit[1], 10, 16)
	if err != nil {
		util.Eprintln("Error parsing server port:", err)
		os.Exit(1)
	}
	config.port = uint16(port)

	serverKey, err := base64.StdEncoding.DecodeString(args[2])
	if err != nil || len(serverKey) != 32 {
		util.Eprintln("Server key has improper formatting")
		os.Exit(1)
	}
	copy(config.key[:], serverKey)

	return config
}

func printUsage() {
	util.Eprintln("Usage: " + os.Args[0] + " [OPTION]... WIREGUARD_INTERFACE SERVER_HOSTNAME:PORT SERVER_PUBKEY")
	util.Eprintln("Flags:")
	pflag.PrintDefaults()
	util.Eprintln("Example:")
	util.Eprintln("    " + os.Args[0] + " wg0 demo.wireguard.com:12345 1rwvlEQkF6vL4jA1gRzlTM7I3tuZHtdq8qkLMwBs8Uw=")
}
