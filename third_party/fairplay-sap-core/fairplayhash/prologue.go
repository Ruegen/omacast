// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"encoding/binary"
)

// NeonPrologueConstants for the NEON prologue arithmetic.
// These are re-loaded from immediates at every round boundary (rounds 1+).
// Round 0 uses the Phase 1 vreg state directly.
const (
	NeonXORConst uint32 = 0x7efd6cfa // vreg[1] constant: XOR mask
	NeonANDConst uint32 = 0xfdfad9f4 // vreg[3] constant: AND mask after SHL
	NeonADDConst uint32 = 0xc1d80000 // vreg[2] constant: final ADD bias
)

// NeonState holds the NEON register state needed for the prologue.
// This is extracted from Phase 1 output registers.
type NeonState struct {
	// Vreg0 is the Phase 1 AES output (payload-dependent).
	// Used directly as hidden[0..3] for round 0 block 0.
	Vreg0 [2]uint64

	// Phase 1 vreg[1..3] — used for round 0 only.
	// For rounds 1+, these are overwritten with the hardcoded constants.
	Vreg1 [2]uint64
	Vreg2 [2]uint64
	Vreg3 [2]uint64
}

// ComputeHiddenWords runs the NEON prologue to produce the 16 hidden words
// for one WB-MD5 round.
//
// For round 0:
//   - Block 0: stores vreg[0] (Phase 1 output) directly as hidden[0..3]
//   - Blocks 1-3: uses Phase 1 vreg[1..3] as XOR/AND/ADD constants
//
// For rounds 1+:
//   - Block 0: loads from x9Data[0..15], transforms with hardcoded constants
//   - Blocks 1-3: same transform with hardcoded constants
//
// Parameters:
//   - ns: NEON register state from Phase 1
//   - x9Data: 64 bytes of memory at x[9]+0x00..x[9]+0x3F
//   - round: which round (0-19) this is for
//
// Returns the 16 hidden words used by the WB-MD5 round.
func ComputeHiddenWords(ns *NeonState, x9Data []byte, round int) [16]uint32 {
	var hidden [16]uint32

	// Select vreg constants based on round
	var xorMask, andMask, addBias [2]uint64
	if round == 0 {
		// Round 0: use Phase 1 vreg state
		xorMask = ns.Vreg1
		andMask = ns.Vreg3
		addBias = ns.Vreg2
	} else {
		// Rounds 1+: constants are re-loaded from immediates
		xorMask = dup32(NeonXORConst)
		andMask = dup32(NeonANDConst)
		addBias = dup32(NeonADDConst)
	}

	if round == 0 {
		// Block 0: Store vreg[0] directly as hidden[0..3]
		hidden[0] = uint32(ns.Vreg0[0])
		hidden[1] = uint32(ns.Vreg0[0] >> 32)
		hidden[2] = uint32(ns.Vreg0[1])
		hidden[3] = uint32(ns.Vreg0[1] >> 32)
	} else {
		// Block 0: Load from x9Data[0..15], transform, store as hidden[0..3]
		v0lo := binary.LittleEndian.Uint64(x9Data[0:])
		v0hi := binary.LittleEndian.Uint64(x9Data[8:])
		h0, h1, h2, h3 := neonBlock(v0lo, v0hi, xorMask, andMask, addBias)
		hidden[0], hidden[1], hidden[2], hidden[3] = h0, h1, h2, h3
	}

	// Block 1: x9Data[0x10..0x1F] → hidden[4..7]
	{
		v0lo := binary.LittleEndian.Uint64(x9Data[0x10:])
		v0hi := binary.LittleEndian.Uint64(x9Data[0x18:])
		h0, h1, h2, h3 := neonBlock(v0lo, v0hi, xorMask, andMask, addBias)
		hidden[4], hidden[5], hidden[6], hidden[7] = h0, h1, h2, h3
	}

	// Block 2: x9Data[0x20..0x2F] → hidden[8..11]
	{
		v0lo := binary.LittleEndian.Uint64(x9Data[0x20:])
		v0hi := binary.LittleEndian.Uint64(x9Data[0x28:])
		h0, h1, h2, h3 := neonBlock(v0lo, v0hi, xorMask, andMask, addBias)
		hidden[8], hidden[9], hidden[10], hidden[11] = h0, h1, h2, h3
	}

	// Block 3: x9Data[0x30..0x3F] → hidden[12..15]
	{
		v0lo := binary.LittleEndian.Uint64(x9Data[0x30:])
		v0hi := binary.LittleEndian.Uint64(x9Data[0x38:])
		h0, h1, h2, h3 := neonBlock(v0lo, v0hi, xorMask, andMask, addBias)
		hidden[12], hidden[13], hidden[14], hidden[15] = h0, h1, h2, h3
	}

	// Inject round counter into hidden[5] MSB.
	// The ARM64 bytecode adds a per-round counter to the most significant byte
	// of word[5]. This counter provides the per-round variation in the WB scheme.
	//   Normal rounds 0-7:   counter = round     (values 0-7)
	//   Normal rounds 10-18: counter = round - 10 (values 0-8)
	//   Rounds 8, 9, 19:     special/skip (handled elsewhere with different HW)
	var counter uint32
	switch {
	case round <= 7:
		counter = uint32(round)
	case round >= 10 && round <= 18:
		counter = uint32(round - 10)
	}
	hidden[5] += counter << 24

	return hidden
}

// dup32 creates a 128-bit NEON register (two uint64 lanes) by duplicating
// a 32-bit value across all 4 lanes.
func dup32(v uint32) [2]uint64 {
	lane := uint64(v) | (uint64(v) << 32)
	return [2]uint64{lane, lane}
}

// neonBlock performs the NEON prologue transformation on one 128-bit block.
//
// The ARM64 NEON sequence is:
//  1. temp = data ^ xorMask          (XOR with constant mask)
//  2. data = (data << 1) & andMask   (SHL by 1, AND with constant)
//  3. data = temp + data             (32-bit lane-wise ADD)
//  4. data = data + addBias          (32-bit lane-wise ADD with bias)
//
// All operations are 32-bit lane-wise on 128-bit (4-lane) vectors.
func neonBlock(v0lo, v0hi uint64, xorMask, andMask, addBias [2]uint64) (w0, w1, w2, w3 uint32) {
	// Step 1: XOR with constant
	xorLo := v0lo ^ xorMask[0]
	xorHi := v0hi ^ xorMask[1]

	// Step 2: SHL by 1 (lane-wise 32-bit), AND with constant
	shlLo := shl32Lanes(v0lo, 1)
	shlHi := shl32Lanes(v0hi, 1)
	andLo := shlLo & andMask[0]
	andHi := shlHi & andMask[1]

	// Step 3: ADD lane-wise 32-bit (xor result + and result)
	addLo := add32Lanes(xorLo, andLo)
	addHi := add32Lanes(xorHi, andHi)

	// Step 4: ADD bias
	resultLo := add32Lanes(addLo, addBias[0])
	resultHi := add32Lanes(addHi, addBias[1])

	return uint32(resultLo), uint32(resultLo >> 32), uint32(resultHi), uint32(resultHi >> 32)
}

// shl32Lanes performs 32-bit lane-wise shift left on a 64-bit value.
func shl32Lanes(v uint64, shift uint) uint64 {
	lo := ((v & 0xFFFFFFFF) << shift) & 0xFFFFFFFF
	hi := (((v >> 32) << shift) & 0xFFFFFFFF) << 32
	return lo | hi
}

// add32Lanes performs 32-bit lane-wise addition on a 64-bit value
// containing two 32-bit lanes (low and high).
func add32Lanes(a, b uint64) uint64 {
	lo := ((a & 0xFFFFFFFF) + (b & 0xFFFFFFFF)) & 0xFFFFFFFF
	hi := (((a >> 32) + (b >> 32)) & 0xFFFFFFFF) << 32
	return lo | hi
}

// g2ShuffleXORConsts are the 8 XOR constants used in the state-dependent
// Fisher-Yates shuffle at the Group 1→2 boundary. Each constant is XORed
// with a 4-bit nibble from the encoded state to produce a swap index.
// Swaps 0-3 use the low nibble (bits 0-3), swaps 4-7 use bits 4-7.
// Register order: a, b, c, d (repeated for each nibble group).
var g2ShuffleXORConsts = [8]uint32{3, 0xd, 0xb, 6, 1, 0, 0xe, 4}

// ShuffleHiddenG2 computes the Group 2-3 hidden words from the Group 0-1
// hidden words using the state-dependent shuffle at the Group 1→2 boundary.
//
// The encoded state values (aEnc, bEnc, cEnc, dEnc) are the raw newB values
// from sub-rounds 28-31 (the 4 most recent encodings at the SR 31→32 boundary).
// These are the values stored in the state registers a, b, c, d BEFORE any
// XOR decode is applied — i.e., newB = postAddB ^ OutBias[i] (or + OutBias for
// ADD-encoded sub-rounds).
func ShuffleHiddenG2(g0 *[16]uint32, aEnc, bEnc, cEnc, dEnc uint32) [16]uint32 {
	h := *g0
	shuffleHiddenG2Into(&h, aEnc, bEnc, cEnc, dEnc)
	return h
}

// ShuffleHiddenG2Reference is the loop as first written, kept as the oracle
// TestShuffleHiddenG2MatchesReference checks the unrolled form against.
func ShuffleHiddenG2Reference(g0 *[16]uint32, aEnc, bEnc, cEnc, dEnc uint32) [16]uint32 {
	h := *g0 // copy
	regs := [4]uint32{aEnc, bEnc, cEnc, dEnc}
	for i := 0; i < 8; i++ {
		reg := regs[i%4]
		var nibble uint32
		if i < 4 {
			nibble = reg & 0xf
		} else {
			nibble = (reg >> 4) & 0xf
		}
		j := int(nibble ^ g2ShuffleXORConsts[i])
		h[i], h[j] = h[j], h[i]
	}
	return h
}

// shuffleHiddenG2Into runs the eight swaps in place, on a buffer the caller has
// already filled with the Group 0-1 words. The swaps are sequential and order
// dependent, so they are written out rather than looped: that removes the
// per-swap nibble branch and the index-constant load.
//
// Every constant in g2ShuffleXORConsts is under 16, so masking the XOR of the
// whole word down to four bits gives the same index as XORing the nibble --
// and unlike the latter it is provably in range, which takes the bounds check
// off all sixteen accesses.
func shuffleHiddenG2Into(h *[16]uint32, aEnc, bEnc, cEnc, dEnc uint32) {
	j := (aEnc ^ 3) & 15
	h[0], h[j] = h[j], h[0]
	j = (bEnc ^ 0xd) & 15
	h[1], h[j] = h[j], h[1]
	j = (cEnc ^ 0xb) & 15
	h[2], h[j] = h[j], h[2]
	j = (dEnc ^ 6) & 15
	h[3], h[j] = h[j], h[3]
	j = (aEnc>>4 ^ 1) & 15
	h[4], h[j] = h[j], h[4]
	j = (bEnc >> 4) & 15
	h[5], h[j] = h[j], h[5]
	j = (cEnc>>4 ^ 0xe) & 15
	h[6], h[j] = h[j], h[6]
	j = (dEnc>>4 ^ 4) & 15
	h[7], h[j] = h[j], h[7]
}

// g2PermTable maps each round's G0 hidden word indices to G2 indices.
// DEPRECATED: This fixed permutation table is incorrect for general inputs.
// Use ShuffleHiddenG2 instead, which performs the correct state-dependent shuffle.
// Kept for reference/test compatibility.
var g2PermTable = [11][16]int{
	{3, 10, 11, 5, 7, 14, 2, 12, 8, 9, 4, 1, 13, 6, 0, 15}, // R0
	{0, 10, 11, 5, 6, 3, 8, 4, 7, 9, 1, 12, 13, 2, 14, 15}, // R1
	{4, 3, 10, 2, 7, 6, 11, 14, 8, 9, 12, 13, 1, 15, 0, 5}, // R2
	{0, 3, 8, 1, 4, 7, 10, 11, 2, 9, 12, 13, 15, 5, 14, 6}, // R3
	{10, 1, 6, 8, 11, 5, 2, 12, 3, 9, 13, 7, 0, 15, 14, 4}, // R4
	{14, 4, 5, 10, 3, 9, 7, 1, 8, 2, 6, 11, 12, 13, 0, 15}, // R5
	{6, 4, 9, 2, 7, 3, 10, 11, 8, 5, 12, 13, 1, 0, 14, 15}, // R6
	{2, 10, 11, 12, 3, 4, 7, 0, 8, 9, 5, 1, 13, 6, 14, 15}, // R7
	{1, 7, 2, 3, 4, 5, 0, 6, 8, 9, 10, 11, 12, 13, 14, 15}, // R8
	{10, 3, 14, 5, 7, 9, 8, 4, 6, 1, 11, 0, 12, 13, 2, 15}, // R10
	{2, 0, 6, 1, 14, 9, 3, 10, 8, 7, 11, 5, 12, 13, 4, 15}, // R19
}

// roundToPermIdx maps round number to g2PermTable index.
// DEPRECATED: See ShuffleHiddenG2.
var roundToPermIdx = [20]int{
	0, 1, 2, 3, 4, 5, 6, 7, // R0-R7
	8,                      // R8
	-1,                     // R9 (skip)
	9,                      // R10
	0, 1, 2, 3, 4, 5, 6, 7, // R11-R18 = R0-R7
	10, // R19
}

// ComputeHiddenWordsG2 applies a fixed permutation to produce G2 hidden words.
// DEPRECATED: This uses a fixed permutation table that is incorrect for general
// inputs. Use ShuffleHiddenG2 or pass nil as hiddenG2 to RoundC_WBMD5_Permuted
// to use the correct state-dependent shuffle.
func ComputeHiddenWordsG2(g0 *[16]uint32, round int) [16]uint32 {
	var g2 [16]uint32
	permIdx := roundToPermIdx[round]
	perm := &g2PermTable[permIdx]
	for j := 0; j < 16; j++ {
		g2[j] = g0[perm[j]]
	}
	return g2
}

// NeonBlockExport exposes neonBlock for cross-package bridge analysis.
func NeonBlockExport(v0lo, v0hi uint64, xorMask, andMask, addBias [2]uint64) (w0, w1, w2, w3 uint32) {
	return neonBlock(v0lo, v0hi, xorMask, andMask, addBias)
}
