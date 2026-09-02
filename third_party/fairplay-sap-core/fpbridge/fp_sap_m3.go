// SPDX-License-Identifier: LGPL-3.0-or-later
// Written here, but modelled on github.com/omarroth/doubletake. See ../NOTICE.md.

package fpbridge

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// m3Prefix is a 144-byte m3 header captured once from a post-m1 emulator
// snapshot. Its 16-byte FPLY framing is genuinely constant, but the 128-byte
// body encodes that snapshot's local SAP, which a real sender is supposed to
// generate per session. See FPSAPExchangeM3 for what that costs.
var m3Prefix, _ = hex.DecodeString(
	"46504c590301030000000098038f1a9c991ea22c511e45ba97f1af8dfb0f86f5" +
		"50c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c7" +
		"12202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b" +
		"7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b691" +
		"01b849fd93a02860d1a0dff5cd4414aa")

// SupportedFPSAPMode is the only FairPlay message mode this package can answer.
//
// An m2 selects a mode in byte 13, and the mode picks both the CBC IV and the
// AES round keys used for the message body -- so the same 128-byte challenge
// produces four entirely different responses under modes 0..3. Our Phase 1 is
// white-box AES over baked T-boxes, and those tables encode mode 3's key
// schedule alone; there is no parameter that could select another.
//
// Verified against omarroth/doubletake, which implements all four: for the same
// payload, FPExchangeNative reproduces their mode 3 byte for byte and matches
// none of modes 0, 1 or 2.
const SupportedFPSAPMode = 3

// FPSAPExchangeM3 computes the FairPlay SAP m3 response for a given m2 message.
// It returns the full 164-byte m3: a 144-byte prefix followed by the 20-byte
// challenge response.
//
// It builds with a plain `go build`, embeds no Apple snapshot, and runs no ARM64
// interpreter. The 20-byte response is the well-tested part: 142/142 archived
// golden vectors, plus eight vectors from two independent emulator-based senders
// (see external_vectors_test.go).
//
// # Two limitations, and only one of them is recoverable by the caller
//
// Mode. An m2 that selects anything other than mode 3 is rejected with an
// error. Answering it would mean emitting a response derived from the wrong key
// schedule -- wrong bytes presented as an answer, which is worse than a refusal.
// Before 2026-08-01 this function ignored byte 13 entirely and replied as though
// every m2 had asked for mode 3.
//
// Session replay. The 144-byte prefix is a constant, so every m3 this function
// emits carries the same local SAP. Real senders generate that SAP per session
// and encrypt it into the m3 body. Receivers that validate the body reject the
// replay: omarroth/doubletake#17 reports RTSP/1.0 466 Key Management Error from
// an AppleTV3,2, and doubletake removed its own hardcoded prefix in e544a88
// (2026-07-20) to fix it. Fixing it here needs a per-session localSAP encrypted
// with the mode's round keys, which this package does not carry.
//
// So: trust FPExchangeBlobless, and treat this framing as a reference that works
// against permissive mode-3 receivers only. Callers wanting broad device
// compatibility need a session-aware m3 body.
func FPSAPExchangeM3(m2 []byte) ([]byte, error) {
	payload, err := parseFPSAPM2(m2)
	if err != nil {
		return nil, err
	}

	hash := FPExchangeBlobless(payload)

	m3 := make([]byte, 164)
	copy(m3[:144], m3Prefix)
	copy(m3[144:], hash[:])
	return m3, nil
}

// parseFPSAPM2 validates a receiver's m2 record and returns its 128-byte
// challenge. An m2 is a 142-byte FPLY record: 12 bytes of framing, then a
// 130-byte payload. Checking the framing rather than just the length is what
// stops a truncated or misaligned buffer being read as a challenge.
func parseFPSAPM2(m2 []byte) (payload [128]byte, err error) {
	if len(m2) != 142 {
		return payload, fmt.Errorf("m2 is %d bytes, want 142", len(m2))
	}
	if string(m2[:4]) != "FPLY" {
		return payload, fmt.Errorf("m2 has magic %x, want FPLY", m2[:4])
	}
	if m2[4] != 3 || m2[5] != 1 || m2[6] != 2 || m2[7] != 0 {
		return payload, fmt.Errorf("m2 has version/type %x, want 03010200", m2[4:8])
	}
	if got := binary.BigEndian.Uint32(m2[8:12]); got != 130 {
		return payload, fmt.Errorf("m2 declares a %d-byte payload, want 130", got)
	}
	if m2[12] != 2 {
		return payload, fmt.Errorf("m2 has payload marker %d, want 2", m2[12])
	}
	if mode := m2[13]; mode != SupportedFPSAPMode {
		return payload, fmt.Errorf("m2 selected FairPlay mode %d; this package answers only mode %d, "+
			"because Phase 1's tables bake that mode's key schedule", mode, SupportedFPSAPMode)
	}
	copy(payload[:], m2[14:142])
	return payload, nil
}

// NewFPSAPM2 builds a well-formed m2 record carrying the given challenge, for
// tests and for callers driving this package from a captured payload rather
// than from a live receiver.
func NewFPSAPM2(mode byte, challenge [128]byte) []byte {
	m2 := make([]byte, 142)
	copy(m2[:4], "FPLY")
	copy(m2[4:8], []byte{3, 1, 2, 0})
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 2
	m2[13] = mode
	copy(m2[14:142], challenge[:])
	return m2
}

// ParseFPSAPM2 validates a receiver's m2 record and returns its 128-byte
// challenge, for callers that want the 20-byte response without a full m3
// frame. Slicing bytes 14:142 out of an m2 by hand skips both the framing check
// and the mode check, which is how a sender ends up answering a mode-0 m2 with
// a mode-3 response.
func ParseFPSAPM2(m2 []byte) ([128]byte, error) { return parseFPSAPM2(m2) }
