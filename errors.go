package proto

import (
	"errors"
)

var (
	// ErrorNotEnoughBytes is returned when the length of the []byte
	// to be decoded does not exceed the minimum header length.
	ErrorNotEnoughBytes = errors.New("proto: not enough bytes available to decode")
)
