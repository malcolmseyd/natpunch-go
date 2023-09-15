# natpunch-go

This is a [NAT hole punching](https://en.wikipedia.org/wiki/UDP_hole_punching) tool designed for creating Wireguard mesh networks. It was inspired by [Tailscale](https://www.tailscale.com/) and informed by [this example](https://git.zx2c4.com/wireguard-tools/tree/contrib/nat-hole-punching/).

This tools allows you to connect to other Wireguard peers from behind a NAT using a server for ip and port discovery. The client is Linux only.

## Usage

The client cycles through each peer on the interface until they are all resolved. Requires root to run due to raw socket usage.
```
Usage: ./client [OPTION]... WIREGUARD_INTERFACE SERVER_HOSTNAME:PORT SERVER_PUBKEY
Flags:
  -c, --continuous=false: continuously resolve peers after they've already been resolved
  -d, --delay=2: time to wait between retries (in seconds)
Example:
    ./client wg0 demo.wireguard.com:12345 1rwvlEQkF6vL4jA1gRzlTM7I3tuZHtdq8qkLMwBs8Uw=
```

The server associates each pubkey to an ip and a port. Doesn't require root to run.
```
Usage: ./server PORT [PRIVATE_KEY]
```

## Why

I want to have a VPN so that I can access all of my devices even when I'm out of the house. Unfortunately, using a traditional client-server model creates additional latency. Peer-to-peer connections are ideal for each client, however many of the devices are behind a NAT. The motivation for this tool was to allow p2p Wireguard connections through a NAT.

## How

UDP NAT hole punching allows us to open a connection when both clients are behind a NAT. Modern NATs may employ source port randomization, which means that clients cannot predict which port to connect to in order to punch through that NAT. We need a way to discover the port that the client is using.

We use a publicly facing server in order to determine the ip address and port of each client. Each client can connect using the same port as Wireguard (by spoofing the source port using raw sockets.) and its ip and port will be recorderd. It can also request the ip and port of another client using their public key. This breaks source port randomization and allows NAT punching on [every NAT type except symmetric](https://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation), as symmetric NATs may use a different external ip and port for each connection.

Once each client gets the ip and port, they simply set the peer's endpoint to the ip and port it learned about and set a persistent keepalive to start the packet flow. With the keepalive, the peers will keep trying to contact each other which will create the hole on both sides and maintain the connection.

## Why Go?

Go has great support for [raw sockets](https://pkg.go.dev/golang.org/x/net/ipv4?tab=doc), [packet filtering](https://pkg.go.dev/golang.org/x/net/bpf?tab=doc), and [packet construction/deconstruction](https://pkg.go.dev/github.com/google/gopacket?tab=doc). I plan on rewriting this in Rust one day but Go's library support is too good to pass up.
