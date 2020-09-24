package main

import (
	"github.com/malcolmseyd/natpunch-go/client/network"
	"github.com/malcolmseyd/natpunch-go/client/util"
	"os"
)

const persistentKeepalive = 25

func main() {
	var err error
	sess := Session{}

	sess.cfg = newConfig()
	sess.server, err = network.NewServer(sess.cfg.hostname, sess.cfg.port, sess.cfg.key)
	if err != nil {
		util.Eprintln("Error configuring server:", err)
		os.Exit(1)
	}

	sess.Run()
}
