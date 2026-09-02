// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

// FPExchangeBlobless computes the full FairPlay SAP m3 response hash (20 bytes)
// from the 128-byte m2 challenge payload, with NO Apple blob of any kind:
//
//	Phase 1  : wbaesFullPhase1 (White-Box AES T-boxes, algorithmic) -> GP buffer
//	Bridge   : computed from the GP buffer -- 9 MD5-family blocks whose messages
//	           and chaining deltas are functions of GP slices, then the output
//	           encoding -> x9Data
//	Phase 2  : fairplayhash.ComputeHashAnalytical (analytical WB-MD5)
//
// It builds with a plain `go build` -- no build tags, no embedded memory
// snapshot, no ARM64 interpreter, and no transliterated template program.
//
// This now delegates to FPExchangeNative. Earlier releases replayed a ~17 MB
// instruction-by-instruction transliteration of Apple's ARM64 bridge; that is
// gone, because the bridge was reduced to an algorithm.
//
// Provenance: reverse-engineered from Apple's FairPlay SAP; defensive
// interoperability research (an authentication handshake, not DRM/content keys).
func FPExchangeBlobless(payload [128]byte) [20]byte {
	return FPExchangeNative(payload)
}

// GPBuffer returns the Phase-1 White-Box AES output ("GP buffer") for a payload.
// Exposed because it is the input downstream ports need for their own Phase-2
// implementations. Pure computation from the baked T-boxes — no blob.
func GPBuffer(payload [128]byte) [128]byte { return wbaesFullPhase1(payload) }
