package proto

type UDPPacket struct {
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	Length          uint16 `json:"length"`
	Checksum        uint16 `json:"checksum"`
	Payload         []byte `json:"payload"`
}

const minUDPPacketSize = 2 + 2 + 2 + 2

// DecodeUDP decodes an UDP packet.
func DecodeUDP(b []byte) (UDPPacket, error) {
	packet := UDPPacket{}

	if len(b) < minUDPPacketSize {
		return packet, ErrorNotEnoughBytes
	}

	i := 0

	packet.SourcePort = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.DestinationPort = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Length = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Checksum = uint16(b[i])<<8 | uint16(b[i+1])
	i += 2

	packet.Payload = b[i:]

	return packet, nil
}
