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
	Source       net.IP `json:"source"`
	Destination  net.IP `json:"destination"`
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

func (p IPv6Packet) Bytes() []byte {
	i := 0
	b := make([]byte, 40+len(p.Payload))

	b[i] = p.Version<<4 | byte(p.TrafficClass>>4)
	b[i+1] = p.TrafficClass<<4 | byte(p.FlowLabel>>16)
	i += 2

	b[i] = byte(p.FlowLabel >> 8)
	b[i+1] = byte(p.FlowLabel)
	i += 2

	b[i] = byte(p.Length >> 8)
	b[i+1] = byte(p.Length)
	i += 2

	b[i] = p.NextHeader
	i++

	b[i] = p.HopLimit
	i++

	copy(b[i:], p.Source)
	i += len(p.Source)

	copy(b[i:], p.Destination)
	i += len(p.Destination)

	copy(b[i:], p.Payload)
	i += len(p.Payload)

	return b[:i]
}
