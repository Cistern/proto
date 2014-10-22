package proto

import (
	"net"
)

type IPv6Packet struct {
	Version      uint8  `json:"version"`
	TrafficClass uint8  `json:"trafficClass"`
	FlowLabel    uint32 `json:"flowLabel"`
	Length       uint16 `json:"length"`
	NextHeader   uint8  `json:"nextHeader"`
	HopLimit     uint8  `json:"hopLimit"`
	Source       net.IP `json:"sourceAddress"`
	Destination  net.IP `json:"destinationAddress"`
	Payload      []byte `json:"payload"`
}

func DecodeIPv6(b []byte) IPv6Packet {
	packet := IPv6Packet{}

	i := 0

	packet.Version = b[i] >> 4
	packet.TrafficClass = uint8(b[i]&0xf)<<4 | uint8(b[i+1]>>4)
	i++

	packet.FlowLabel = uint32(b[i]&0xf)<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
	i += 3

	packet.Length = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.NextHeader = uint8(b[i])
	i++

	packet.HopLimit = uint8(b[i])
	i++

	packet.Source = net.IP(b[i : i+16])
	i += 16

	packet.Destination = net.IP(b[i : i+16])
	i += 16

	packet.Payload = b[i:]

	return packet
}
