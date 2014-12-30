package proto

import (
	"net"
)

// IPv4Packet represents an IPv4 packet.
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

const minIPv4PacketSize = 1 + 1 + 1 + 1 + 2 + 2 + 1 + 2 + 1 + 1 + 2 + 4 + 4

// DecodeIPv4 decodes an IPv4 packet.
func DecodeIPv4(b []byte) (IPv4Packet, error) {
	packet := IPv4Packet{}

	if len(b) < minIPv4PacketSize {
		return packet, ErrorNotEnoughBytes
	}

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

	return packet, nil
}

// Bytes returns an encoded IPv4 packet.
func (p IPv4Packet) Bytes() []byte {
	i := 0

	var b []byte

	if p.InternetHeaderLength > 5 {
		b = make([]byte, (24)+len(p.Payload))
	} else {
		b = make([]byte, (20)+len(p.Payload))
	}

	b[i] = byte(p.Version)<<4 | byte(p.InternetHeaderLength)
	i++

	b[i] = byte(p.DSCP)<<2 | byte(p.ECN)
	i++

	b[i] = byte(p.Length >> 8)
	b[i+1] = byte(p.Length)
	i += 2

	b[i] = byte(p.Identification >> 8)
	b[i+1] = byte(p.Identification)
	i += 2

	b[i] = p.Flags<<5 | byte(p.FragmentationOffset>>8)
	b[i+1] = byte(p.FragmentationOffset)
	i += 2

	b[i] = p.TimeToLive
	i++

	b[i] = p.Protocol
	i++

	b[i] = byte(p.HeaderChecksum >> 8)
	b[i+1] = byte(p.HeaderChecksum)
	i += 2

	copy(b[i:], p.Source)
	i += 4

	copy(b[i:], p.Destination)
	i += 4

	if p.InternetHeaderLength > 5 {
		copy(b[i:], p.Options)
		i += 4
	}

	copy(b[i:], p.Payload)
	i += len(p.Payload)

	return b[:i]
}

// ComputeChecksum returns the checksum for the IPv4 packet.
func (p IPv4Packet) ComputeChecksum() uint16 {
	sum := ((uint32(p.Version)<<4|uint32(p.InternetHeaderLength))<<8 |
		(uint32(p.DSCP)<<2 | uint32(p.ECN))) +
		uint32(p.Length) +
		uint32(p.Identification) +
		(uint32(p.Flags)<<13 | uint32(p.FragmentationOffset)) +
		(uint32(p.TimeToLive)<<8 | uint32(p.Protocol)) +
		(uint32(p.Source[0])<<8 | uint32(p.Source[1])) +
		(uint32(p.Source[2])<<8 | uint32(p.Source[3])) +
		(uint32(p.Destination[0])<<8 | uint32(p.Destination[1])) +
		(uint32(p.Destination[2])<<8 | uint32(p.Destination[3]))

	return uint16(0xffff) ^ (uint16(sum>>16) + uint16(sum))
}
