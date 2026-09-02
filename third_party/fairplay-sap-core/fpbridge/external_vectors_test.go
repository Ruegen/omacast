// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"encoding/hex"
	"testing"
)

// The vectors below come from two AirPlay senders that compute the FairPlay SAP
// exchange by emulating Apple's signed ARM64 binary. Neither derives from this
// project's reverse engineering, so agreement with them is independent evidence
// that the recovered algebra in FPExchangeBlobless is correct.
//
// Sources, pinned:
//
//	nored/airfry @ master     rust/fpemu/tests/vectors.txt      (CORE_IN/CORE_OUT)
//	omarroth/doubletake @ 8ccea5f  internal/airplay/fpsap_test.go
//	                          (TestFPSAPExchangeGoldenVectors)
//
// doubletake's expectations are the output of
// fpsapExchangeForSAP(fpsapReferenceLocalSAP(), decryptFPSAPBody(3, payload)) —
// its reference local SAP is the same frozen post-m1 state our m3Prefix encodes,
// which is why the interfaces line up. See TestM3PrefixIsFrozenSession for the
// limitation that follows from that.

func mustHexVec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector hex: %v", err)
	}
	return b
}

func TestExternalGoldenVectors(t *testing.T) {
	capturedM2 := mustHexVec(t, "46504c59030102000000008202034a114c26b77d4e2eec2c8f89fdb653b5b3"+
		"2d3576bc176816d110a14c3f53c08dbb936183bfdfe0a4f3c12e85216003b46f738c40c54da6c436d29d1"+
		"b342d63c7b314309ae79a33bb1787709ef077cbfe4190117a3423e270fd1a2eac44da1a7934f59dc681d1"+
		"b70783f228c4d077c2d495f5285c3bf8df586fc2ebfe17fb5b65")

	filled := func(v byte) (p [128]byte) {
		for i := range p {
			p[i] = v
		}
		return
	}
	sparse := func(i int) (p [128]byte) {
		p[i] = 0x42
		return
	}
	ramp := func() (p [128]byte) {
		for i := range p {
			p[i] = byte(i)
		}
		return
	}
	fromM2 := func() (p [128]byte) {
		copy(p[:], capturedM2[14:142])
		return
	}

	tests := []struct {
		name    string
		origin  string
		payload [128]byte
		want    string
	}{
		{"ramp-0x00-0x7f", "airfry CORE_IN/CORE_OUT", ramp(), "84449e19d306930b66942aacfb71395a903878ef"},
		{"all-zeros", "doubletake", [128]byte{}, "6f627565f3e77f5b5ede91beee7baf92e4241e0b"},
		{"all-ff", "doubletake", filled(0xff), "dc2cc74f2ed55484f59f95b96082f0f5c017dd17"},
		{"captured-m2", "doubletake", fromM2(), "4b911e48af23d8406368aeafbb61bfcd569e3e55"},
		{"0x42-at-0", "doubletake", sparse(0), "9bfb9556b8659c2ac94b7ef9e587d71e159ea624"},
		{"0x42-at-63", "doubletake", sparse(63), "150d9fa4eb456e73ba48de5779c5c996b16b3b23"},
		{"0x42-at-64", "doubletake", sparse(64), "a167db30424ff8890d085c0f1c92b2c5cc06fc45"},
		{"0x42-at-127", "doubletake", sparse(127), "d246ec5e7adc8118994b8df77146529486ac7caf"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FPExchangeBlobless(tc.payload)
			if gotHex := hex.EncodeToString(got[:]); gotHex != tc.want {
				t.Fatalf("FPExchangeBlobless disagrees with %s\n got = %s\nwant = %s",
					tc.origin, gotHex, tc.want)
			}
		})
	}
}

// TestM3PrefixIsFrozenSession pins the known limitation of the framing layer
// rather than the correctness of the core.
//
// FPSAPExchangeM3 emits a constant 144-byte prefix whose 128-byte body encodes a
// local SAP captured once from a post-m1 emulator snapshot. A receiver that
// checks the body against the session rejects it: omarroth/doubletake#17
// reports RTSP/1.0 466 Key Management Error from an AppleTV3,2, and doubletake
// fixed it in e544a88 by generating the local SAP per session.
//
// This test exists so the constant cannot be mistaken for a protocol invariant.
// It should be deleted when the framing layer generates a fresh local SAP.
func TestM3PrefixIsFrozenSession(t *testing.T) {
	var challenge [128]byte
	m2 := NewFPSAPM2(SupportedFPSAPMode, challenge)

	a, err := FPSAPExchangeM3(m2)
	if err != nil {
		t.Fatal(err)
	}
	m2[20] ^= 0xff
	b, err := FPSAPExchangeM3(m2)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(a[:144]) != hex.EncodeToString(b[:144]) {
		t.Fatal("m3 prefix varied with the payload; the framing layer may already " +
			"be session-aware — if so, delete this test")
	}
	if hex.EncodeToString(a[144:]) == hex.EncodeToString(b[144:]) {
		t.Fatal("m3 tail did not vary with the payload; the exchange is not " +
			"consuming its input")
	}
}
