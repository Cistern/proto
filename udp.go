package protodecode

type UDPPacket struct {
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	Length          uint16 `json:"length"`
	Checksum        uint16 `json:"checksum"`
	Payload         []byte `json:"payload"`
}

func DecodeUDP(b []byte) UDPPacket {
	packet := UDPPacket{}

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

	return packet
}
