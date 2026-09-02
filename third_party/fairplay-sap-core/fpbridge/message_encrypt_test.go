// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"encoding/hex"
	"testing"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fpsapcore"
)

// TestEncryptReproducesFrozenPrefix validates the m3 body encryption against the
// one ciphertext this repository already holds.
//
// m3Prefix was captured whole from an emulator snapshot, and fpsapcore carries
// that same session's local SAP as plaintext because the bridge needs it. So the
// pair (plaintext, ciphertext) was already here, unused, and encrypting one must
// reproduce the other exactly.
//
// This is a real check rather than a restatement: the two constants came from
// different places -- the ciphertext from an m3 frame captured on the wire, the
// plaintext from the descriptor input the bridge was solved against -- and the
// round keys came from a third, omarroth/doubletake. Nothing here would agree by
// construction if any of the three were wrong.
func TestEncryptReproducesFrozenPrefix(t *testing.T) {
	got := fpsapcore.EncryptMessageBodyMode3(fpsapcore.FrozenLocalSAP())
	want := m3Prefix[16:144]

	if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
		t.Fatalf("encrypting the frozen local SAP did not reproduce m3Prefix[16:144]:\n got  %x\n want %x",
			got[:], want)
	}
	t.Logf("✅ encrypt(frozen localSAP) == m3Prefix[16:144], 128/128 bytes")
}

// TestFrozenLocalSAPShape pins the two protocol-fixed bytes at the head of a
// local SAP: a real sender writes 00 01 there and fills the rest opaquely.
func TestFrozenLocalSAPShape(t *testing.T) {
	sap := fpsapcore.FrozenLocalSAP()
	if sap[0] != 0x00 || sap[1] != 0x01 {
		t.Errorf("local SAP starts %02x %02x, want 00 01", sap[0], sap[1])
	}
}
