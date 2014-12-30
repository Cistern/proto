package proto

import (
	"net"
)

// EthernetFrame represents an Ethernet frame.
type EthernetFrame struct {
	Destination net.HardwareAddr `json:"source"`
	Source      net.HardwareAddr `json:"destination"`
	VlanTag     uint32           `json:"vlanTag"`
	EtherType   uint16           `json:"etherType"`
	Payload     []byte           `json:"payload"`
}

const minEthernetFrameSize = 6 + 6 + 4 + 2

// DecodeEthernet decodes an Ethernet frame.
func DecodeEthernet(b []byte) (EthernetFrame, error) {
	frame := EthernetFrame{}

	if len(b) < minEthernetFrameSize {
		return frame, ErrorNotEnoughBytes
	}

	i := 0 // Just a helper for indexing.

	// Decode MAC addresses.
	frame.Destination = net.HardwareAddr(b[i : i+6])
	i += 6
	frame.Source = net.HardwareAddr(b[i : i+6])
	i += 6

	// Check for a VLAN tag.
	if b[i] == 0x81 && b[i+1] == 0x00 {
		i += 2
		frame.VlanTag = uint32(0x81<<24) | uint32(0x00<<16) | uint32(b[i]<<8) | uint32(b[i+1])
		i += 2
	}

	// Check the Ethernet type
	if t := uint16(b[i])<<8 | uint16(b[i+1]); t >= 1536 { // If 1500 or less, it's the payload length.
		frame.EtherType = t
	}

	i += 2

	frame.Payload = b[i:]

	return frame, nil
}

// Bytes returns an encoded Ethernet frame.
func (f EthernetFrame) Bytes() []byte {
	i := 0

	b := make([]byte, (6+6+4+2)+len(f.Payload))

	copy(b, f.Destination[:])
	i += 6
	copy(b[i:], f.Source[:])
	i += 6

	if f.VlanTag != 0 {
		b[i] = 0x81
		b[i+1] = 0x00
		i += 2

		b[i] = byte(f.VlanTag >> 8)
		b[i+1] = byte(f.VlanTag)

		i += 2
	}

	if f.EtherType != 0 {
		b[i] = byte(f.EtherType >> 8)
		b[i+1] = byte(f.EtherType)
	} else {
		l := len(f.Payload)
		b[i] = byte(l >> 8)
		b[i+1] = byte(l)
	}

	i += 2

	copy(b[i:], f.Payload)

	return b[:i+len(f.Payload)]
}
