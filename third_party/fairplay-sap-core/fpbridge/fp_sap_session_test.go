// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpsapcore"
)

// TestSessionWithFrozenSAPMatchesFrozenPath is the check that makes the
// session-aware path trustworthy.
//
// Drive a session with the *frozen* local SAP and it must reproduce, byte for
// byte, what FPSAPExchangeM3 emits from the captured prefix — for all 142 golden
// vectors, across the whole 164-byte frame. That exercises every piece the new
// path adds at once: the forward AES body encryption, the general descriptor
// that cannot use the precomputed first two blocks, and the framing built from
// scratch rather than spliced from a capture.
//
// A disagreement anywhere in those three would show here, because the frozen
// path is pinned to 142 archived vectors and to a prefix captured on the wire.
func TestSessionWithFrozenSAPMatchesFrozenPath(t *testing.T) {
	s := &FPSAPSession{localSAP: fpsapcore.FrozenLocalSAP()}

	rows := loadGolden(t)
	checked := 0
	for _, rec := range rows {
		if len(rec) < 4 {
			continue
		}
		pb, _ := hex.DecodeString(rec[2])
		if len(pb) != 128 {
			continue
		}
		var challenge [128]byte
		copy(challenge[:], pb)
		m2 := NewFPSAPM2(SupportedFPSAPMode, challenge)

		frozen, err := FPSAPExchangeM3(m2)
		if err != nil {
			t.Fatalf("%s: frozen path: %v", rec[0], err)
		}
		session, err := s.ExchangeM3(m2)
		if err != nil {
			t.Fatalf("%s: session path: %v", rec[0], err)
		}
		if !bytes.Equal(frozen, session) {
			t.Fatalf("%s: session m3 differs from the frozen path\n session %x\n frozen  %x",
				rec[0], session, frozen)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no golden vectors were checked")
	}
	t.Logf("✅ %d/%d golden vectors: session path reproduces the frozen 164-byte m3 exactly", checked, checked)
}

// TestSessionsDiffer is the point of the type: two sessions must not emit the
// same frame, in either the body or the response.
func TestSessionsDiffer(t *testing.T) {
	var challenge [128]byte
	for i := range challenge {
		challenge[i] = byte(i*11 + 5)
	}
	m2 := NewFPSAPM2(SupportedFPSAPMode, challenge)

	a, err := NewFPSAPSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFPSAPSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if a.LocalSAP() == b.LocalSAP() {
		t.Fatal("two sessions drew the same local SAP")
	}

	m3a, err := a.ExchangeM3(m2)
	if err != nil {
		t.Fatal(err)
	}
	m3b, err := b.ExchangeM3(m2)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(m3a[16:144], m3b[16:144]) {
		t.Error("two sessions encrypted the same m3 body")
	}
	if bytes.Equal(m3a[144:], m3b[144:]) {
		t.Error("two sessions produced the same response; the local SAP is not " +
			"reaching the descriptor")
	}
	if !bytes.Equal(m3a[:16], m3b[:16]) {
		t.Error("the FPLY framing varied between sessions; it is protocol-fixed")
	}
	if !bytes.Equal(m3a[:16], m3Prefix[:16]) {
		t.Errorf("session framing %x does not match the captured prefix %x",
			m3a[:16], m3Prefix[:16])
	}
}

// TestSessionLocalSAPShape checks the two protocol-fixed head bytes are written.
func TestSessionLocalSAPShape(t *testing.T) {
	s, err := NewFPSAPSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sap := s.LocalSAP()
	if sap[0] != 0x00 || sap[1] != 0x01 {
		t.Errorf("local SAP starts %02x %02x, want 00 01", sap[0], sap[1])
	}
}

// TestSessionRejectsBadM2 checks the session path validates identically.
func TestSessionRejectsBadM2(t *testing.T) {
	s, err := NewFPSAPSession(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var challenge [128]byte
	for _, mode := range []byte{0, 1, 2, 4, 255} {
		if _, err := s.ExchangeM3(NewFPSAPM2(mode, challenge)); err == nil {
			t.Errorf("mode %d was answered", mode)
		}
	}
	if _, err := s.ExchangeM3(make([]byte, 142)); err == nil {
		t.Error("an all-zero m2 was answered")
	}
}
