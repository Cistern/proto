package proto

// TCPPacket represents a TCP packet.
type TCPPacket struct {
	SourcePort            uint16 `json:"sourcePort"`
	DestinationPort       uint16 `json:"destinationPort"`
	SequenceNumber        uint32 `json:"sequenceNumber"`
	AcknowledgementNumber uint32 `json:"acknowledgementNumber"`
	DataOffset            uint8  `json:"dataOffset"`

	// We have 9 bits of flags
	// so we're going to waste a
	// few bits of space using a
	// uint16.
	Flags uint16 `json:"flags"`

	WindowSize    uint16 `json:"windowSize"`
	Checksum      uint16 `json:"checksum"`
	UrgentPointer uint16 `json:"urgentPointer"`

	Options []byte `json:"options"`
	Payload []byte `json:"payload"`
}

const minTCPPacketSize = 2 + 2 + 4 + 4 + 1 + 2 + 2 + 2 + 2

// HasFIN returns true if the FIN flag is set.
func (p TCPPacket) HasFIN() bool {
	return p.Flags&(1<<0) > 0
}

// HasSYN returns true if the SYN flag is set.
func (p TCPPacket) HasSYN() bool {
	return p.Flags&(1<<1) > 0
}

// HasRST return true if the RST flag is set.
func (p TCPPacket) HasRST() bool {
	return p.Flags&(1<<2) > 0
}

// HasPSH returns true if the PSH flag is set.
func (p TCPPacket) HasPSH() bool {
	return p.Flags&(1<<3) > 0
}

// HasACK returns true if the ACK flag is set.
func (p TCPPacket) HasACK() bool {
	return p.Flags&(1<<4) > 0
}

// HasURG returns true if the URG flag is set.
func (p TCPPacket) HasURG() bool {
	return p.Flags&(1<<5) > 0
}

// HasECE returns true if the ECE flag is set.
func (p TCPPacket) HasECE() bool {
	return p.Flags&(1<<6) > 0
}

// HasCWR returns true if the CWR flag is set.
func (p TCPPacket) HasCWR() bool {
	return p.Flags&(1<<7) > 0
}

// HasNS returns true if the NS flag is set.
func (p TCPPacket) HasNS() bool {
	return p.Flags>>8 > 0
}

// DecodeTCP decodes an TCP packet.
func DecodeTCP(b []byte) (TCPPacket, error) {
	packet := TCPPacket{}

	if len(b) < minTCPPacketSize {
		return packet, ErrorNotEnoughBytes
	}

	i := 0

	packet.SourcePort = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.DestinationPort = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.SequenceNumber = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
	i += 4

	packet.AcknowledgementNumber = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
	i += 4

	packet.DataOffset = b[i] >> 4
	packet.Flags = uint16(b[i]&1)<<8 | uint16(b[i+1])
	i += 2

	packet.WindowSize = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Checksum = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.UrgentPointer = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Options = b[i : int(packet.DataOffset)*4]

	i = int(packet.DataOffset) * 4

	packet.Payload = b[i:]

	return packet, nil
}
