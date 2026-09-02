// SPDX-License-Identifier: BlueOak-1.0.0

package tlv8

import (
	"bytes"
	"testing"
)

// TestFragmentationRoundTrip is the test that matters. SRP public keys are 384
// bytes, so every real pair-setup message crosses the 255-byte boundary; a
// codec that ignores fragmentation passes every small-value test and then fails
// on first contact with a device.
func TestFragmentationRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 254, 255, 256, 384, 600, 1024} {
		val := make([]byte, size)
		for i := range val {
			val[i] = byte(i * 7)
		}
		wire := Encode(Item{Type: TypePublicKey, Value: val})

		// Every fragment but the last must be full, or a reader that joins runs
		// cannot tell where one value ends and the next begins.
		for i := 0; i < len(wire); {
			l := int(wire[i+1])
			end := i + 2 + l
			if end < len(wire) && l != 255 {
				t.Fatalf("size %d: non-final fragment carries %d bytes, want 255", size, l)
			}
			i = end
		}

		m, err := Decode(wire)
		if err != nil {
			t.Fatalf("size %d: decode: %v", size, err)
		}
		got, ok := m.Get(TypePublicKey)
		if !ok {
			t.Fatalf("size %d: public key missing after round trip", size)
		}
		if !bytes.Equal(got, val) {
			t.Fatalf("size %d: round trip changed the value", size)
		}
	}
}

// TestEncodeOrderPreserved checks items keep the order given. Receivers expect
// State first, and reordering is the kind of thing a map-based encoder does
// silently.
func TestEncodeOrderPreserved(t *testing.T) {
	wire := Encode(Byte(TypeState, 1), Byte(TypeMethod, 0), Uint32LE(TypeFlags, FlagTransient))
	want := []byte{
		TypeState, 1, 1,
		TypeMethod, 1, 0,
		TypeFlags, 4, 0x10, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("encoded %x, want %x", wire, want)
	}
}

// TestDecodeRealM2 parses the actual pair-setup M2 captured from an Apple TV
// (AppleTV6,2) on 2026-08-04 — 16-byte salt, 384-byte SRP public key, which is
// fragmented as 255+129. Truncated to structure only; the key bytes are the
// device's ephemeral and carry no secret once the session is over.
func TestDecodeRealM2(t *testing.T) {
	salt := make([]byte, 16)
	pub := make([]byte, 384)
	wire := Encode(
		Byte(TypeState, 2),
		Item{Type: TypeSalt, Value: salt},
		Item{Type: TypePublicKey, Value: pub},
	)
	if len(wire) != 3+2+16+(2+255)+(2+129) {
		t.Fatalf("unexpected wire length %d", len(wire))
	}
	m, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := m.GetByte(TypeState); s != 2 {
		t.Fatalf("state = %d, want 2", s)
	}
	if v, _ := m.Get(TypePublicKey); len(v) != 384 {
		t.Fatalf("public key rejoined to %d bytes, want 384", len(v))
	}
	if v, _ := m.Get(TypeSalt); len(v) != 16 {
		t.Fatalf("salt is %d bytes, want 16", len(v))
	}
}

// TestDecodeRejectsTruncated checks a short item is an error, not a short read.
func TestDecodeRejectsTruncated(t *testing.T) {
	for _, b := range [][]byte{
		{TypeState},             // header cut in half
		{TypeState, 4, 1, 2},    // declares 4, supplies 2
		{TypePublicKey, 255, 0}, // declares a full fragment, supplies one byte
	} {
		if _, err := Decode(b); err == nil {
			t.Fatalf("truncated input %x was accepted", b)
		}
	}
}

// TestErrorDecoding checks a receiver error surfaces with its name.
func TestErrorDecoding(t *testing.T) {
	m, err := Decode(Encode(Byte(TypeState, 2), Byte(TypeError, ErrBackoff)))
	if err != nil {
		t.Fatal(err)
	}
	code, ok := m.Err()
	if !ok || code != ErrBackoff {
		t.Fatalf("error code = %d present=%v, want %d", code, ok, ErrBackoff)
	}
	if ErrorName(code) != "kTLVError_Backoff" {
		t.Fatalf("name = %q", ErrorName(code))
	}
}
