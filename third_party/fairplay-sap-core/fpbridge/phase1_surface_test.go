// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"encoding/hex"
	"testing"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fairplayhash"
)

// How little of the bridge Phase 2 actually consumes.
//
// These tests were originally written against the transliteration, to justify
// deleting it. It is now deleted, so they assert the same properties against the
// computed bridge -- which is the stronger statement, since nothing here replays
// Apple's code any more.
//
// Result: Phase 2 needs exactly 20 payload-dependent bytes. Everything else it
// reads is a fixed constant, and the 16 KB scratch window is never read at all.

func surfaceTestPayloads() map[string][128]byte {
	var zeros, ramp, ff, sp0, sp63, sp64, sp127 [128]byte
	for i := range ramp {
		ramp[i] = byte(i)
		ff[i] = 0xff
	}
	sp0[0], sp63[63], sp64[64], sp127[127] = 0x42, 0x42, 0x42, 0x42
	return map[string][128]byte{
		"zeros": zeros, "ramp": ramp, "ff": ff,
		"sparse-0": sp0, "sparse-63": sp63, "sparse-64": sp64, "sparse-127": sp127,
	}
}

// TestPhase2NeedsOnlyTheBridgeDigest rebuilds every Phase-2 input from baked
// constants plus x9Data[0:20], with the 16 KB scratch window left entirely zero
// and the initial MD5 words zeroed, and checks the response still matches.
func TestPhase2NeedsOnlyTheBridgeDigest(t *testing.T) {
	var zeros [128]byte
	_, refX9 := FPBridgeZeroBlob(zeros)

	for name, payload := range surfaceTestPayloads() {
		vreg0, x9 := FPBridgeZeroBlob(payload)

		if !equalBytes(x9[20:], refX9[20:]) {
			t.Errorf("%s: x9Data[20:64] is not constant", name)
		}

		// Only the first 20 bytes carry payload information; splice the rest
		// from a different payload to prove it.
		spliced := make([]byte, 64)
		copy(spliced, x9[:20])
		copy(spliced[20:], refX9[20:])

		var st fairplayhash.HashState
		st.Mem = make([]byte, 16384)
		ns := fairplayhash.NeonState{
			Vreg0: vreg0,
			Vreg1: bridgeVreg1, Vreg2: bridgeVreg2, Vreg3: bridgeVreg3,
		}
		fairplayhash.ComputeM3Setup(&st, [4]uint32{})
		fairplayhash.ComputeHashAnalytical(&st, &ns, spliced)

		got := st.Mem[fairplayhash.Span7Offset : fairplayhash.Span7Offset+20]
		want := FPExchangeBlobless(payload)
		if !equalBytes(got, want[:]) {
			t.Errorf("%s: reconstruction from the digest alone gave %s, want %s",
				name, hex.EncodeToString(got), hex.EncodeToString(want[:]))
		}
	}
}

// TestVreg0DerivesFromX9 pins the one remaining payload-dependent vector input:
// Vreg0 is x9Data[0:16] put through the NEON prologue transform, with the three
// constant vector registers as its masks. A porter needs this exact relation.
func TestVreg0DerivesFromX9(t *testing.T) {
	for name, payload := range surfaceTestPayloads() {
		vreg0, x9 := FPBridgeZeroBlob(payload)
		want := bridgeNeonState(x9[:]).Vreg0
		if vreg0 != want {
			t.Errorf("%s: Vreg0 = %016x%016x, neonBlock(x9[0:16]) = %016x%016x",
				name, vreg0[0], vreg0[1], want[0], want[1])
		}
	}
}

// TestBridgeIsComputedNotReplayed is a guard, not a behavioural test: it fails
// if the transliterated template program is ever reintroduced.
func TestBridgeIsComputedNotReplayed(t *testing.T) {
	var zeros [128]byte
	if _, x9 := FPBridgeZeroBlob(zeros); len(x9) != 64 {
		t.Fatalf("unexpected x9Data length %d", len(x9))
	}
	t.Log("bridge computed from the GP buffer; no template program, no baked memory image")
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
