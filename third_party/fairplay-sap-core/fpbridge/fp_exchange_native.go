// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import (
	"sync"

	"github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/fairplayhash"
)

// FPExchangeNative computes the FairPlay SAP m3 response (20 bytes) from the
// 128-byte m2 challenge with no interpreter and no transliterated code:
//
//	Phase 1 : wbaesFullPhase1        -> the 128-byte GP buffer
//	Bridge  : 9 MD5-family blocks, messages and chaining deltas computed from
//	          GP slices, then the output encoding -> x9Data
//	Phase 2 : fairplayhash.ComputeHashAnalytical
//
// It differs from FPExchangeBlobless only in the middle step. FPExchangeBlobless
// is blobless but not algorithmic: it still replays a transliteration of Apple's
// ARM64 bridge against a baked memory image. This computes the same thing.
//
// Phase 2's real input surface is narrow, and measured rather than assumed
// (TestLayerDPhase2* ): it never reads the 16KB scratch window or initialMD5,
// x9Data[0:16] reaches it only through Vreg0, and Vreg1..3 are constants. So a
// zeroed scratch buffer is correct here, not a shortcut.
// scratchPool recycles the 16 KB Phase-2 window. Its incoming contents cannot
// affect the result -- TestLayerDPhase2ReadsAlgoMem overwrites the whole window
// with zeros, 0xFF and random bytes and the m3 does not move -- so buffers are
// returned to the pool without being cleared.
// Pooling a pointer rather than the slice keeps Get/Put from boxing a slice
// header into an interface, which is itself an allocation.
var scratchPool = sync.Pool{New: func() any { return new([16384]byte) }}

func FPExchangeNative(payload [128]byte) [20]byte {
	gp := wbaesFullPhase1(payload)
	x9 := bridgeX9DataClosed(gp)
	return exchangeFromX9(x9[:])
}

// exchangeFromX9 runs Phase 2 over a bridge digest. Split out so a session-aware
// exchange, whose digest depends on its own local SAP, shares this path exactly.
func exchangeFromX9(x9Data []byte) [20]byte {
	ns := bridgeNeonState(x9Data)

	mem := scratchPool.Get().(*[16384]byte)
	defer scratchPool.Put(mem)

	state := fairplayhash.HashState{Mem: mem[:]}
	fairplayhash.ComputeM3Setup(&state, [4]uint32{})
	fairplayhash.ComputeHashAnalytical(&state, &ns, x9Data)

	var result [20]byte
	copy(result[:], state.Mem[fairplayhash.Span7Offset:fairplayhash.Span7Offset+20])
	return result
}
