package proto

import (
	"testing"
)

func TestMultilayerDecode(t *testing.T) {
	b := []byte{
		0, 15, 248, 20, 48, 0, 0, 37, 144, 82, 230, 31,
		134, 221, 96, 0, 0, 0, 0, 40, 6, 64, 38, 32, 1,
		0, 80, 7, 0, 6, 0, 0, 0, 0, 0, 1, 0, 3, 38, 32,
		1, 0, 80, 7, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 217,
		104, 0, 80, 184, 89, 70, 22, 0, 0, 0, 0, 160, 2,
		22, 128, 239, 131, 0, 0, 2, 4, 5, 160, 4, 2, 8,
		10, 184, 73, 195, 65, 0, 0, 0, 0, 1, 3, 3, 7,
	}

	ethernetFrame := DecodeEthernet(b)
	if ethernetFrame.EtherType != 0x86dd {
		t.Fatalf("expected to see EtherType %x, got %x", 0x86dd, ethernetFrame.EtherType)
	}

	ipv6Packet := DecodeIPv6(ethernetFrame.Payload)
	if ipv6Packet.NextHeader != 0x6 {
		t.Fatalf("expected to see NextHeader %x, got %x", 0x6, ipv6Packet.NextHeader)
	}

	tcpPacket := DecodeTCP(ipv6Packet.Payload)
	if tcpPacket.DestinationPort != 80 {
		t.Fatalf("expected to see destination port %v, got %v", 80, tcpPacket.DestinationPort)
	}

	if !tcpPacket.HasSYN() {
		t.Error("expected to see SYN set")
	}

	if tcpPacket.HasACK() {
		t.Error("ACK flag set when it should not be")
	}
}

func BenchmarkMultilayerDecode(b *testing.B) {
	buf := [...]byte{
		0, 15, 248, 20, 48, 0, 0, 37, 144, 82, 230, 31,
		134, 221, 96, 0, 0, 0, 0, 40, 6, 64, 38, 32, 1,
		0, 80, 7, 0, 6, 0, 0, 0, 0, 0, 1, 0, 3, 38, 32,
		1, 0, 80, 7, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 217,
		104, 0, 80, 184, 89, 70, 22, 0, 0, 0, 0, 160, 2,
		22, 128, 239, 131, 0, 0, 2, 4, 5, 160, 4, 2, 8,
		10, 184, 73, 195, 65, 0, 0, 0, 0, 1, 3, 3, 7,
	}

	for i := 0; i < b.N; i++ {
		ethernetFrame := DecodeEthernet(buf[:])
		ipv6Packet := DecodeIPv6(ethernetFrame.Payload)
		DecodeTCP(ipv6Packet.Payload)
	}
}
