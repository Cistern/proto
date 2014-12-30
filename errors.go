package proto

import (
	"errors"
)

var (
	ErrorNotEnoughBytes = errors.New("proto: not enough bytes available to decode")
)
