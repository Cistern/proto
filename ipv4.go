package protodecode

import (
	"net"
)

type IPv4Packet struct {
	Version              uint8
	InternetHeaderLength uint8
	DSCP                 uint8
	ECN                  uint8
	Length               uint16
	Identification       uint16
	Flags                uint8
	FragmentationOffset  uint16
	TimeToLive           uint8
	Protocol             uint8
	HeaderChecksum       uint16
	Source               net.IP
	Destination          net.IP
	Options              []byte
	Payload              []byte
}

func DecodeIPv4(b []byte) IPv4Packet {
	packet := IPv4Packet{}

	i := 0

	packet.Version = uint8(b[i] >> 4)
	packet.InternetHeaderLength = uint8(b[i] & 0xf)
	i++

	packet.DSCP = uint8(b[i] >> 2)
	packet.ECN = uint8(b[i] & 0x3)
	i++

	packet.Length = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Identification = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Flags = uint8(b[i] >> 5)
	packet.FragmentationOffset = uint16(b[i]&0x1f)<<8 | uint16(b[i+1])
	i += 2

	packet.TimeToLive = uint8(b[i])
	i++

	packet.Protocol = uint8(b[i])
	i++

	packet.HeaderChecksum = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Source = net.IPv4(b[i], b[i+1], b[i+2], b[i+3])
	i += 4

	packet.Destination = net.IPv4(b[i], b[i+1], b[i+2], b[i+3])
	i += 4

	packet.Options = b[i : int(packet.InternetHeaderLength)*4]

	i = int(packet.InternetHeaderLength) * 4

	packet.Payload = b[i:]

	return packet
}
