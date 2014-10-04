package protodecode

import (
	"net"
)

type IPv4Packet struct {
	Version              uint8  `json:"version"`
	InternetHeaderLength uint8  `json:"internetHeaderLength"`
	DSCP                 uint8  `json:"dscp"`
	ECN                  uint8  `json:"ecn"`
	Length               uint16 `json:"length"`
	Identification       uint16 `json:"indentification"`
	Flags                uint8  `json:"flags"`
	FragmentationOffset  uint16 `json:"fragmentationOffset"`
	TimeToLive           uint8  `json:"timeToLive"`
	Protocol             uint8  `json:"protocol"`
	HeaderChecksum       uint16 `json:"headerChecksum"`
	Source               net.IP `json:"source"`
	Destination          net.IP `json:"destination"`
	Options              []byte `json:"options"`
	Payload              []byte `json:"payload"`
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

	packet.Source = net.IP(b[i : i+4])
	i += 4

	packet.Destination = net.IP(b[i : i+4])
	i += 4

	packet.Options = b[i : int(packet.InternetHeaderLength)*4]

	i = int(packet.InternetHeaderLength) * 4

	packet.Payload = b[i:]

	return packet
}
