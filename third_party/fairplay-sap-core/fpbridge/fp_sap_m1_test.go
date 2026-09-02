// SPDX-License-Identifier: LGPL-3.0-or-later
package fpbridge

import (
	"encoding/binary"
	"testing"
)

// TestNewFPSAPM1Framing pins the record shape against the same rules
// parseFPSAPM2 enforces for m2, so the two cannot drift apart.
func TestNewFPSAPM1Framing(t *testing.T) {
	m1 := NewFPSAPM1(FPSAPFullCapabilities)

	if len(m1) != 16 {
		t.Fatalf("m1 is %d bytes, want 16", len(m1))
	}
	if string(m1[:4]) != "FPLY" {
		t.Errorf("magic %q, want FPLY", m1[:4])
	}
	if got, want := m1[4:8], []byte{3, 1, 1, 0}; string(got) != string(want) {
		t.Errorf("version/type %x, want %x", got, want)
	}
	if got := binary.BigEndian.Uint32(m1[8:12]); got != 4 {
		t.Errorf("declared payload length %d, want 4", got)
	}
	if got, want := m1[12:], []byte{0x02, 0x00, FPSAPFullCapabilities, 0xbb}; string(got) != string(want) {
		t.Errorf("payload %x, want %x", got, want)
	}

	// The framing must match the m3 we emit, which came from a wire capture --
	// same magic and same version byte, differing only in the message type.
	if m1[0] != m3Prefix[0] || m1[4] != m3Prefix[4] || m1[5] != m3Prefix[5] {
		t.Errorf("m1 framing %x diverges from the captured m3 prefix %x", m1[:8], m3Prefix[:8])
	}
	if m1[6] == m3Prefix[6] {
		t.Errorf("m1 and m3 both claim message type %d", m1[6])
	}
}

// TestM1CapabilitiesIsNotAMode guards the confusion the doc comment warns about:
// the capability mask and the message mode are different fields that both reach
// 3, and a refactor that conflated them would still compile.
func TestM1CapabilitiesIsNotAMode(t *testing.T) {
	m1 := NewFPSAPM1(0)
	if m1[14] != 0 {
		t.Fatalf("capability byte did not follow the argument")
	}
	// Clearing capabilities must not touch anything a mode lives in.
	full := NewFPSAPM1(FPSAPFullCapabilities)
	for i := range m1 {
		if i == 14 {
			continue
		}
		if m1[i] != full[i] {
			t.Errorf("byte %d changed with the capability mask: %02x vs %02x", i, m1[i], full[i])
		}
	}
}
