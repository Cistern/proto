package proto

import (
	"reflect"
	"testing"
)

func TestIPv6(t *testing.T) {
	b := []byte{
		96, 0, 0, 0, 0, 40, 6, 64, 38, 32, 1, 0,
		80, 7, 0, 6, 0, 0, 0, 0, 0, 1, 0, 3, 38,
		32, 1, 0, 80, 7, 0, 2, 0, 0, 0, 0, 0, 0,
		0, 2, 217, 103, 0, 80, 145, 114, 114, 15,
		0, 0, 0, 0, 160, 2, 22, 128, 91, 254, 0,
		0, 2, 4, 5, 160, 4, 2, 8, 10, 184, 68, 81,
		187, 0, 0, 0, 0, 1, 3, 3, 7,
	}

	packet := DecodeIPv6(b)

	if packet.Destination.String() != "2620:100:5007:2::2" {
		t.Errorf("expected destination address %v, got %v",
			"2620:100:5007:2::2", packet.Destination)
	}
}

func TestIPv6Encode(t *testing.T) {
	packet := IPv6Packet{
		Version:      0x6,
		TrafficClass: 0x0,
		FlowLabel:    0x0,
		Length:       0x28,
		NextHeader:   0x6,
		HopLimit:     0x40,
		Source:       []byte{0x26, 0x20, 0x1, 0x0, 0x50, 0x7, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3},
		Destination:  []byte{0x26, 0x20, 0x1, 0x0, 0x50, 0x7, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2},
		Payload: []uint8{0xd9, 0x67, 0x0, 0x50, 0x91, 0x72, 0x72,
			0xf, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0x16, 0x80, 0x5b,
			0xfe, 0x0, 0x0, 0x2, 0x4, 0x5, 0xa0, 0x4, 0x2, 0x8,
			0xa, 0xb8, 0x44, 0x51, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x1,
			0x3, 0x3, 0x7,
		},
	}

	p := DecodeIPv6(packet.Bytes())

	if !reflect.DeepEqual(packet, p) {
		t.Error("Encoded and decoded IPv6 packets not equal:", packet, p)
	}

	if p.Destination.String() != "2620:100:5007:2::2" {
		t.Errorf("expected destination address %v, got %v",
			"2620:100:5007:2::2", packet.Destination)
	}
}

func BenchmarkIPv6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b := []byte{
			96, 0, 0, 0, 0, 40, 6, 64, 38, 32, 1, 0,
			80, 7, 0, 6, 0, 0, 0, 0, 0, 1, 0, 3, 38,
			32, 1, 0, 80, 7, 0, 2, 0, 0, 0, 0, 0, 0,
			0, 2, 217, 103, 0, 80, 145, 114, 114, 15,
			0, 0, 0, 0, 160, 2, 22, 128, 91, 254, 0,
			0, 2, 4, 5, 160, 4, 2, 8, 10, 184, 68, 81,
			187, 0, 0, 0, 0, 1, 3, 3, 7,
		}

		DecodeIPv6(b)
	}
}
