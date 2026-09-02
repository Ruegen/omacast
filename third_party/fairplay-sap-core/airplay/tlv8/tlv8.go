// SPDX-License-Identifier: BlueOak-1.0.0

// Package tlv8 encodes and decodes the type-length-value format HomeKit-style
// pairing uses for pair-setup and pair-verify bodies.
//
// The format is trivial — one byte of type, one byte of length, then that many
// bytes of value — with one wrinkle that matters: a value longer than 255 bytes
// is split across consecutive items carrying the *same* type byte, and a reader
// must concatenate a same-type run back into one value. SRP's 384-byte public
// keys always hit this, so a codec that ignores fragmentation appears to work
// right up until the first real exchange.
package tlv8

import "fmt"

// Item types used by pair-setup and pair-verify.
const (
	TypeMethod        byte = 0x00
	TypeIdentifier    byte = 0x01
	TypeSalt          byte = 0x02
	TypePublicKey     byte = 0x03
	TypeProof         byte = 0x04
	TypeEncryptedData byte = 0x05
	TypeState         byte = 0x06
	TypeError         byte = 0x07
	TypeRetryDelay    byte = 0x08
	TypeCertificate   byte = 0x09
	TypeSignature     byte = 0x0A
	TypePermissions   byte = 0x0B
	TypeFragmentData  byte = 0x0C
	TypeFragmentLast  byte = 0x0D
	TypeACL           byte = 0x12
	TypeFlags         byte = 0x13
	TypeSeparator     byte = 0xFF
)

// FlagTransient is the pair-setup flag selecting transient pairing: one SRP
// exchange, no stored long-term key, and no PIN for the user to type.
const FlagTransient uint32 = 0x10

// Error codes a receiver can return in a TypeError item.
const (
	ErrUnknown        byte = 0x01
	ErrAuthentication byte = 0x02
	ErrBackoff        byte = 0x03
	ErrMaxPeers       byte = 0x04
	ErrMaxTries       byte = 0x05
	ErrUnavailable    byte = 0x06
	ErrBusy           byte = 0x07
)

var errNames = map[byte]string{
	ErrUnknown: "kTLVError_Unknown", ErrAuthentication: "kTLVError_Authentication",
	ErrBackoff: "kTLVError_Backoff", ErrMaxPeers: "kTLVError_MaxPeers",
	ErrMaxTries: "kTLVError_MaxTries", ErrUnavailable: "kTLVError_Unavailable",
	ErrBusy: "kTLVError_Busy",
}

// ErrorName renders a receiver error code for humans, falling back to the
// number so an unrecognised code is still reportable.
func ErrorName(code byte) string {
	if n, ok := errNames[code]; ok {
		return n
	}
	return fmt.Sprintf("unknown TLV error 0x%02x", code)
}

// Item is one logical type/value pair, before or after fragmentation.
type Item struct {
	Type  byte
	Value []byte
}

// Byte is a convenience constructor for the many single-byte items.
func Byte(t, v byte) Item { return Item{Type: t, Value: []byte{v}} }

// Uint32LE builds a little-endian 4-byte item, the encoding TypeFlags uses.
func Uint32LE(t byte, v uint32) Item {
	return Item{Type: t, Value: []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}}
}

// Encode serialises items in the order given, fragmenting any value longer
// than 255 bytes into consecutive same-type items. Order is preserved because
// receivers care about it — State and Method come first in every message.
func Encode(items ...Item) []byte {
	var out []byte
	for _, it := range items {
		v := it.Value
		if len(v) == 0 {
			out = append(out, it.Type, 0)
			continue
		}
		for len(v) > 0 {
			n := len(v)
			if n > 255 {
				n = 255
			}
			out = append(out, it.Type, byte(n))
			out = append(out, v[:n]...)
			v = v[n:]
		}
	}
	return out
}

// Map is a decoded message: one entry per type, with fragmented runs joined.
type Map map[byte][]byte

// Decode parses a message, concatenating consecutive items that share a type.
// A truncated or over-long item is an error rather than a silent short read —
// a half-parsed pairing message must not look like a valid one.
func Decode(b []byte) (Map, error) {
	out := Map{}
	for i := 0; i < len(b); {
		if i+2 > len(b) {
			return nil, fmt.Errorf("tlv8: truncated header at offset %d", i)
		}
		t, l := b[i], int(b[i+1])
		if i+2+l > len(b) {
			return nil, fmt.Errorf("tlv8: item type 0x%02x at offset %d declares %d bytes, only %d remain",
				t, i, l, len(b)-i-2)
		}
		out[t] = append(out[t], b[i+2:i+2+l]...)
		i += 2 + l
	}
	return out, nil
}

// Get returns a value, reporting whether it was present.
func (m Map) Get(t byte) ([]byte, bool) { v, ok := m[t]; return v, ok }

// GetByte returns a single-byte value such as State or Method.
func (m Map) GetByte(t byte) (byte, bool) {
	v, ok := m[t]
	if !ok || len(v) != 1 {
		return 0, false
	}
	return v[0], true
}

// Err returns the receiver's error code if the message carries one.
func (m Map) Err() (byte, bool) { return m.GetByte(TypeError) }
