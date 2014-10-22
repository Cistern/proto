package proto

import (
	"testing"
)

func TestUDP(t *testing.T) {
	b := []byte{
		238, 1, 0, 53, 0, 47, 5, 247,
		253, 88, 1, 32, 0, 1, 0, 0, 0,
		0, 0, 1, 6, 103, 111, 111, 103,
		108, 101, 3, 99, 111, 109, 0, 0,
		1, 0, 1, 0, 0, 41, 16, 0, 0, 0,
		0, 0, 0, 0,
	}

	udpPacket := DecodeUDP(b)

	if udpPacket.DestinationPort != 53 {
		t.Errorf("expected destination port %v, got %v", 53, udpPacket.DestinationPort)
	}
}

func BenchmarkUDP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b := []byte{
			238, 1, 0, 53, 0, 47, 5, 247,
			253, 88, 1, 32, 0, 1, 0, 0, 0,
			0, 0, 1, 6, 103, 111, 111, 103,
			108, 101, 3, 99, 111, 109, 0, 0,
			1, 0, 1, 0, 0, 41, 16, 0, 0, 0,
			0, 0, 0, 0,
		}

		DecodeUDP(b)
	}
}
