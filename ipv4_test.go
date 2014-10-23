package proto

import (
	"reflect"
	"testing"
)

func TestIPv4(t *testing.T) {
	b := []byte{
		69, 0, 0, 126, 186, 180, 64, 0, 64, 6, 151, 204,
		192, 168, 0, 103,
		173, 194, 121, 39,
		187, 33, 0, 80, 130, 127, 178, 159, 110, 68, 148, 175, 128, 24, 0,
		229, 76, 61, 0, 0, 1, 1, 8, 10, 0, 63, 8, 48, 14, 52, 9, 77, 71, 69,
		84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 85, 115, 101,
		114, 45, 65, 103, 101, 110, 116, 58, 32, 99, 117, 114, 108, 47, 55,
		46, 51, 53, 46, 48, 13, 10, 72, 111, 115, 116, 58, 32, 103, 111, 111,
		103, 108, 101, 46, 99, 111, 109, 13, 10, 65, 99, 99, 101, 112, 116,
		58, 32, 42, 47, 42, 13, 10, 13, 10,
	}

	packet := DecodeIPv4(b)
	if packet.Source.String() != "192.168.0.103" {
		t.Errorf("expected source IPv4 address %v, got %v", "192.168.0.103", packet.Source)
	}

	if checksum := packet.ComputeChecksum(); checksum != packet.HeaderChecksum {
		t.Errorf("expected checksum %x, computed %x", packet.HeaderChecksum, checksum)
	}
}

func TestIPv4Encode(t *testing.T) {
	packet := IPv4Packet{
		Version:              4,
		InternetHeaderLength: 5,
		DSCP:                 0,
		ECN:                  0x0,
		Length:               0x7e,
		Identification:       0xbab4,
		Flags:                0x2,
		FragmentationOffset:  0x0,
		TimeToLive:           0x40,
		Protocol:             0x6,
		Source:               []byte{0xc0, 0xa8, 0x0, 0x67},
		Destination:          []byte{0xad, 0xc2, 0x79, 0x27},
		Options:              []uint8{},
		Payload: []uint8{
			0xbb, 0x21, 0x0, 0x50, 0x82, 0x7f, 0xb2, 0x9f,
			0x6e, 0x44, 0x94, 0xaf, 0x80, 0x18, 0x0, 0xe5,
			0x4c, 0x3d, 0x0, 0x0, 0x1, 0x1, 0x8, 0xa, 0x0,
			0x3f, 0x8, 0x30, 0xe, 0x34, 0x9, 0x4d, 0x47,
			0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54,
			0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa, 0x55,
			0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e,
			0x74, 0x3a, 0x20, 0x63, 0x75, 0x72, 0x6c, 0x2f,
			0x37, 0x2e, 0x33, 0x35, 0x2e, 0x30, 0xd, 0xa,
			0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x67, 0x6f,
			0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
			0xd, 0xa, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74,
			0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0xd, 0xa, 0xd, 0xa,
		},
	}

	packet.HeaderChecksum = packet.ComputeChecksum()

	decoded := DecodeIPv4(packet.Bytes())

	if !reflect.DeepEqual(packet, decoded) {
		t.Error("Encoded and decoded Ethernet frames not equal:", decoded, packet)
	}
}

func BenchmarkIPv4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b := []byte{
			69, 0, 0, 126, 186, 180, 64, 0, 64, 6, 151, 204,
			192, 168, 0, 103,
			173, 194, 121, 39,
			187, 33, 0, 80, 130, 127, 178, 159, 110, 68, 148, 175, 128, 24, 0,
			229, 76, 61, 0, 0, 1, 1, 8, 10, 0, 63, 8, 48, 14, 52, 9, 77, 71, 69,
			84, 32, 47, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 85, 115, 101,
			114, 45, 65, 103, 101, 110, 116, 58, 32, 99, 117, 114, 108, 47, 55,
			46, 51, 53, 46, 48, 13, 10, 72, 111, 115, 116, 58, 32, 103, 111, 111,
			103, 108, 101, 46, 99, 111, 109, 13, 10, 65, 99, 99, 101, 112, 116,
			58, 32, 42, 47, 42, 13, 10, 13, 10,
		}

		DecodeIPv4(b)
	}
}
