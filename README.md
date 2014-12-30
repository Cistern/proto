proto [![Build Status](https://drone.io/github.com/PreetamJinka/proto/status.png)](https://drone.io/github.com/PreetamJinka/proto/latest) [![GoDoc](https://godoc.org/github.com/PreetamJinka/proto?status.svg)](https://godoc.org/github.com/PreetamJinka/proto) [![BSD License](https://img.shields.io/pypi/l/Django.svg)]()
====
Lean, mean protocol decoding and encoding.

Usage
---
```go
package main

import (
	"log"

	"github.com/PreetamJinka/proto"
)

func main() {
	b := []byte{
		0, 15, 248, 20, 48, 0, 0, 37, 144, 82, 230, 31,
		134, 221, 96, 0, 0, 0, 0, 40, 6, 64, 38, 32, 1,
		0, 80, 7, 0, 6, 0, 0, 0, 0, 0, 1, 0, 3, 38, 32,
		1, 0, 80, 7, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 217,
		104, 0, 80, 184, 89, 70, 22, 0, 0, 0, 0, 160, 2,
		22, 128, 239, 131, 0, 0, 2, 4, 5, 160, 4, 2, 8,
		10, 184, 73, 195, 65, 0, 0, 0, 0, 1, 3, 3, 7,
	}

	ethernetFrame, err := proto.DecodeEthernet(b)
	if err != nil {
		log.Fatal(err)
	}

	if ethernetFrame.EtherType != 0x86dd {
		log.Fatalf("expected to see EtherType %x, got %x", 0x86dd, ethernetFrame.EtherType)
	}

	ipv6Packet, err := proto.DecodeIPv6(ethernetFrame.Payload)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Decoded an IPv6 packet: %#+v", ipv6Packet)

	if ipv6Packet.NextHeader != 0x6 {
		log.Fatalf("expected to see NextHeader %x, got %x", 0x6, ipv6Packet.NextHeader)
	}

	tcpPacket, err := proto.DecodeTCP(ipv6Packet.Payload)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Decoded a TCP packet: %#+v", tcpPacket)
}

```

Notes
---
Payloads are sub-sliced, not copied, so you might want to make copies if you're reusing
buffers that you're decoding.

TCP and UDP encoding is not implemented.

License
---
BSD (see LICENSE)
