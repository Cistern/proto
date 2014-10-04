package protodecode

import (
	"net"
)

type IPv6Packet struct {
	Version            uint8
	TrafficClass       uint8
	FlowLabel          uint32
	PayloadLength      uint16
	NextHeader         uint8
	HopLimit           uint8
	SourceAddress      net.IP
	DestinationAddress net.IP
	Payload            []byte
}

func DecodeIPv6(b []byte) IPv6Packet {
	packet := IPv6Packet{}

	i := 0

	packet.Version = b[i] >> 4
	packet.TrafficClass = uint8(b[i]&0xf)<<4 | uint8(b[i+1]>>4)
	i += 1

	packet.FlowLabel = uint32(b[i]&0xf)<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
	i += 3

	packet.PayloadLength = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.NextHeader = uint8(b[i])
	i++

	packet.HopLimit = uint8(b[i])
	i++

	packet.SourceAddress = net.IP(b[i : i+16])
	i += 16

	packet.DestinationAddress = net.IP(b[i : i+16])
	i += 16

	packet.Payload = b[i:]

	return packet
}
