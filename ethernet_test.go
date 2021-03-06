package proto

import (
	"net"
	"reflect"
	"testing"
)

func TestEthernet(t *testing.T) {
	b := []byte{
		156, 78, 54, 89, 178, 84,
		232, 222, 39, 187, 107, 170,
		8, 0,
		69, 32, 0, 71, 159, 133, 0, 0, 41, 17, 112, 72,
		192, 168, 0, 1,
		192, 168, 0, 103,
		0, 53, 111, 47, 0, 51, 144, 128, 126, 47, 129, 128,
		0, 1, 0, 1, 0, 0, 0, 0, 6, 109, 105, 115, 102, 114,
		97, 2, 109, 101, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0,
		1, 0, 0, 84, 7, 0, 4, 199, 58, 162, 130,
	}

	frame, err := DecodeEthernet(b)
	if err != nil {
		t.Fatal(err)
	}

	if frame.Source.String() != "e8:de:27:bb:6b:aa" {
		t.Error("Got the wrong source MAC:", frame.Source.String())
	}
}

func TestEthernetEncode(t *testing.T) {
	e := EthernetFrame{
		Source:      net.HardwareAddr{0x9c, 0x4e, 0x36, 0x59, 0xb2, 0x54},
		Destination: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		VlanTag:     0,
		EtherType:   0x0800,
		Payload:     []byte("foobarbaz"),
	}

	b := e.Bytes()

	frame, err := DecodeEthernet(b)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(frame, e) {
		t.Error("Encoded and decoded Ethernet frames not equal:", frame, e)
	}
}

func BenchmarkEthernet(b *testing.B) {
	buf := [...]byte{
		156, 78, 54, 89, 178, 84,
		232, 222, 39, 187, 107, 170,
		8, 0,
		69, 32, 0, 71, 159, 133, 0, 0, 41, 17, 112, 72,
		192, 168, 0, 1,
		192, 168, 0, 103,
		0, 53, 111, 47, 0, 51, 144, 128, 126, 47, 129, 128,
		0, 1, 0, 1, 0, 0, 0, 0, 6, 109, 105, 115, 102, 114,
		97, 2, 109, 101, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0,
		1, 0, 0, 84, 7, 0, 4, 199, 58, 162, 130,
	}

	for i := 0; i < b.N; i++ {
		DecodeEthernet(buf[:])
	}
}
