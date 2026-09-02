// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"encoding/binary"
)

// DebugRoundOutputs and DebugRoundAShort are the legacy package-level capture
// slots populated by ComputeHash.
//
// DEPRECATED / NOT CONCURRENCY-SAFE: because these are package globals written
// on every round, calling ComputeHash from multiple goroutines is a data race
// (confirmed under -race). Batch/corpus code must use ComputeHashInto with a
// per-goroutine HashTrace instead.
var DebugRoundOutputs [20][16]byte

// DebugRoundAShort captures the 16 bytes at RoundAShortOffset (3184) right after
// the RoundA-short bswap in each round. Reverse-engineering (Session 36,
// TestMixTableTaint_*) showed the 144-byte "mixing table" that feeds TailSPN is
// 9 snapshots of exactly this area, taken at the last 9 rounds. Used to derive
// the mixing table analytically without the bytecode interpreter.
//
// DEPRECATED / NOT CONCURRENCY-SAFE — see DebugRoundOutputs.
var DebugRoundAShort [20][16]byte

// HashTrace holds the per-round intermediates ComputeHash used to publish via
// package globals. One HashTrace per goroutine makes the hash batch-safe.
type HashTrace struct {
	// RoundOutputs is the raw 4-word MD5 state post-RoundC, pre-bswap and
	// pre-writeback, for each round. Consumed by FinalizeSpan7.
	RoundOutputs [20][4]uint32
	// RoundAShort is the 16 bytes at RoundAShortOffset after the short bswap.
	RoundAShort [20][16]byte
}

// ComputeHash computes the FairPlay Phase 2 hash from Phase 1 output state.
// This replaces 78,874 ARM64 interpreter instructions with native Go.
//
// The Phase 2 hash is a 20-round ARX block cipher:
//
//	Setup → (RoundC → RoundA_short → Setup → RoundB → RoundA_long → Finalize) × 20
//
// Where:
//
//	RoundC = White-Box MD5 (64 sub-rounds, affine bijection encoding)
//	RoundA = bswap32 on state words
//	RoundB = T-box constant expansion (15 XOR iterations per round)
//
// Parameters:
//   - state: HashState with Mem sliced to start at SP (SP-relative offsets)
//   - ns: NEON register state from Phase 1 (vreg[0..3])
//   - x9Data: 64 bytes at x[9]+0x00..x[9]+0x3F (NEON prologue source data)
//
// Performance target: <50µs on Apple Silicon (vs 340µs interpreter)
func ComputeHash(state *HashState, ns *NeonState, x9Data []byte) {
	var tr HashTrace
	ComputeHashInto(state, ns, x9Data, &tr)

	// Legacy global publication (see the DebugRoundOutputs doc comment).
	for r := 0; r < 20; r++ {
		for w := 0; w < 4; w++ {
			binary.LittleEndian.PutUint32(DebugRoundOutputs[r][w*4:], tr.RoundOutputs[r][w])
		}
	}
	DebugRoundAShort = tr.RoundAShort
}

// ComputeHashInto is ComputeHash with all per-round captures written to tr
// instead of package globals, and with no mutation of the caller's x9Data.
// It touches no shared mutable state, so it is safe to call concurrently.
func ComputeHashInto(state *HashState, ns *NeonState, x9Data []byte, tr *HashTrace) {
	// Capture raw RoundC outputs for span7 finalization.
	// Each round's 4 MD5 state words (post-RoundC, pre-bswap) are needed
	// to compute the XOR fold that produces span7[0:4].
	roundOutputs := &tr.RoundOutputs

	// ComputeHash historically patched x9Data[52:56] in place after round 0,
	// mutating the caller's slice. Work on a private copy instead.
	x9 := make([]byte, len(x9Data))
	copy(x9, x9Data)

	// Save the initial MD5 state for each msg area offset.
	// The ARM64 bytecode executes rounds INDEPENDENTLY: each round reads
	// the initial state (not accumulated output from the previous round).
	// The inter-round code restores the initial state after each RoundC.
	//
	// Only three distinct offsets exist (3360, 3568, 3272), so a small keyed
	// array beats a per-call map allocation.
	var initKeys [3]int
	var initVals [3][4]uint32
	nInit := 0
	initialStateOf := func(offset int) [4]uint32 {
		for i := 0; i < nInit; i++ {
			if initKeys[i] == offset {
				return initVals[i]
			}
		}
		return [4]uint32{}
	}
	setInitialState := func(offset int, v [4]uint32) {
		for i := 0; i < nInit; i++ {
			if initKeys[i] == offset {
				initVals[i] = v
				return
			}
		}
		initKeys[nInit], initVals[nInit] = offset, v
		nInit++
	}
	for _, offset := range RoundMsgAreaOffset {
		seen := false
		for i := 0; i < nInit; i++ {
			if initKeys[i] == offset {
				seen = true
				break
			}
		}
		if !seen {
			var s [4]uint32
			for w := 0; w < 4; w++ {
				s[w] = binary.LittleEndian.Uint32(state.Mem[offset+w*4:])
			}
			setInitialState(offset, s)
		}
	}

	// Write the R8/R19 initial state to offset 3568.
	// The bytecode's inter-round code (BB at PC=0x1a12a2364) writes this
	// constant to SP+3568 before rounds 8 and 19. It is payload-independent
	// (verified across payloads 0x00, 0x01, 0x42, 0xFF).
	setInitialState(3568, round8InitialState)
	for w := 0; w < 4; w++ {
		binary.LittleEndian.PutUint32(state.Mem[3568+w*4:], round8InitialState[w])
	}

	for round := 0; round < 20; round++ {
		// Round 9 is a state-restoration round (see ComputeHashLegacy comment).
		// Skip RoundC; RoundA/RoundB are no-ops for round 9.
		if round == 9 {
			roundA_bswap(state, RoundAShortOffset, RoundAShortCount)
			roundB_constExpand(state, round)
			roundA_bswap(state, RoundALongOffset, RoundALongCount)
			continue
		}

		// 1. Compute hidden words for RoundC.
		// Rounds 8 and 19 have special hidden words derived from stack frame
		// metadata (different SP offsets, nested function calls). Use hardcoded
		// tables for those. Normal rounds use dynamic NEON prologue computation.
		var hiddenG0 [16]uint32
		var hiddenG2 *[16]uint32 // nil → computed by RoundC via state-dependent shuffle
		if round == 8 || round == 19 {
			hiddenG0 = HiddenWordsG0[round]
			g2 := HiddenWordsG2[round]
			hiddenG2 = &g2
		} else {
			hiddenG0 = ComputeHiddenWords(ns, x9, round)
		}

		// 2. RoundC: White-Box MD5 on state words.
		// Each round starts from the INITIAL state (independent rounds).
		var md5State [4]uint32
		readState(state, &md5State, round)

		RoundC_WBMD5_Permuted(&md5State, &hiddenG0, hiddenG2)

		// Capture raw output before writing back / bswap
		roundOutputs[round] = md5State

		writeState(state, &md5State, round)

		// 3. RoundA short: bswap 4 words at state offset
		roundA_bswap(state, RoundAShortOffset, RoundAShortCount)

		// Capture the RoundA-short area — the mixing table that feeds TailSPN is
		// 9 snapshots of exactly this 16-byte area (Session 36 RE).
		copy(tr.RoundAShort[round][:], state.Mem[RoundAShortOffset:RoundAShortOffset+16])

		// 4. RoundB: T-box constant expansion
		roundB_constExpand(state, round)

		// 5. RoundA long: bswap 14 words
		roundA_bswap(state, RoundALongOffset, RoundALongCount)

		// 6. Restore initial MD5 state at the msg area offset.
		// The bytecode's inter-round code resets the state so each round
		// reads the original initial MD5, not the accumulated output.
		offset := RoundMsgAreaOffset[round]
		init := initialStateOf(offset)
		for w := 0; w < 4; w++ {
			binary.LittleEndian.PutUint32(state.Mem[offset+w*4:], init[w])
		}

		// x9Data evolution: the bytecode's WB-MD5 sub-rounds write to a memory
		// location that aliases x9Data[52:56]. After round 0, this byte becomes
		// 0x00380ae0 (constant, payload-independent). This affects hidden[13]
		// for all subsequent rounds.
		if round == 0 && len(x9) >= 56 {
			binary.LittleEndian.PutUint32(x9[52:], 0x00380ae0)
		}
	}

	// Finalize: assemble span7 from round outputs
	FinalizeSpan7(state, roundOutputs)
}

// ComputeHashDebug is like ComputeHash but returns the raw round outputs
// for diagnostic testing. It does NOT call FinalizeSpan7.
func ComputeHashDebug(state *HashState, ns *NeonState, x9Data []byte) [20][4]uint32 {
	var roundOutputs [20][4]uint32

	initialState := make(map[int][4]uint32)
	for _, offset := range RoundMsgAreaOffset {
		if _, ok := initialState[offset]; !ok {
			var s [4]uint32
			for w := 0; w < 4; w++ {
				s[w] = binary.LittleEndian.Uint32(state.Mem[offset+w*4:])
			}
			initialState[offset] = s
		}
	}
	initialState[3568] = round8InitialState
	for w := 0; w < 4; w++ {
		binary.LittleEndian.PutUint32(state.Mem[3568+w*4:], round8InitialState[w])
	}

	for round := 0; round < 20; round++ {
		if round == 9 {
			roundA_bswap(state, RoundAShortOffset, RoundAShortCount)
			roundB_constExpand(state, round)
			roundA_bswap(state, RoundALongOffset, RoundALongCount)
			continue
		}

		var hiddenG0 [16]uint32
		var hiddenG2 *[16]uint32 // nil → computed by RoundC via state-dependent shuffle
		if round == 8 || round == 19 {
			hiddenG0 = HiddenWordsG0[round]
			g2 := HiddenWordsG2[round]
			hiddenG2 = &g2
		} else {
			hiddenG0 = ComputeHiddenWords(ns, x9Data, round)
		}

		var md5State [4]uint32
		readState(state, &md5State, round)
		RoundC_WBMD5_Permuted(&md5State, &hiddenG0, hiddenG2)
		roundOutputs[round] = md5State
		writeState(state, &md5State, round)

		roundA_bswap(state, RoundAShortOffset, RoundAShortCount)
		roundB_constExpand(state, round)
		roundA_bswap(state, RoundALongOffset, RoundALongCount)

		offset := RoundMsgAreaOffset[round]
		init := initialState[offset]
		for w := 0; w < 4; w++ {
			binary.LittleEndian.PutUint32(state.Mem[offset+w*4:], init[w])
		}

		// x9Data evolution: see ComputeHash for full comment.
		if round == 0 && len(x9Data) >= 56 {
			binary.LittleEndian.PutUint32(x9Data[52:], 0x00380ae0)
		}
	}

	return roundOutputs
}

// ComputeHashLegacy is the old ComputeHash that uses hardcoded hidden word tables.
// Kept for comparison testing — will be removed once dynamic version is verified.
func ComputeHashLegacy(state *HashState) {
	for round := 0; round < 20; round++ {
		// Round 9 is a state-restoration round: in the ARM64 binary, the
		// inter-round code between rounds 8→9 temporarily modifies @3272,
		// and round 9's BB restores it to the initial IV. Since our Go code
		// doesn't replicate those inter-round modifications, @3272 already
		// has the correct value and round 9's RoundC is a no-op.
		// (RoundBTbox[9] is all-zeros, so RoundA/RoundB are also no-ops.)
		if round == 9 {
			roundA_bswap(state, RoundAShortOffset, RoundAShortCount)
			roundB_constExpand(state, round)
			roundA_bswap(state, RoundALongOffset, RoundALongCount)
			continue
		}

		var md5State [4]uint32
		readState(state, &md5State, round)

		var hiddenG0, hiddenG2 [16]uint32
		readHiddenWords(state, &hiddenG0, &hiddenG2, round)

		roundC_withPermutedHidden(&md5State, &hiddenG0, &hiddenG2)

		writeState(state, &md5State, round)

		roundA_bswap(state, RoundAShortOffset, RoundAShortCount)
		roundB_constExpand(state, round)
		roundA_bswap(state, RoundALongOffset, RoundALongCount)
	}
}

// roundC_withPermutedHidden performs WB-MD5 with separate hidden word arrays
// for groups 0-1 (original) and groups 2-3 (after permutation).
func roundC_withPermutedHidden(state *[4]uint32, hiddenG0, hiddenG2 *[16]uint32) {
	// The WB-MD5 uses hiddenG0 for sub-rounds 0-31 (groups 0-1)
	// and hiddenG2 for sub-rounds 32-63 (groups 2-3).
	// We simulate this by calling the same MD5 logic but switching
	// the msg source at the group boundary.

	a, b, c, d := state[0], state[1], state[2], state[3]

	// encRound tracks which round's outBias encodes each state word.
	aEnc, bEnc, cEnc, dEnc := -1, -1, -1, -1

	for i := 0; i < 64; i++ {
		// Decode state words
		aDec := a
		if aEnc >= 0 {
			aDec = a ^ OutBiases[aEnc]
		}
		bDec := b
		if bEnc >= 0 {
			bDec = b ^ OutBiases[bEnc]
		}
		cDec := c
		if cEnc >= 0 {
			cDec = c ^ OutBiases[cEnc]
		}
		dDec := d
		if dEnc >= 0 {
			dDec = d ^ OutBiases[dEnc]
		}

		// Standard MD5 F-function
		var f uint32
		switch i >> 4 {
		case 0:
			f = dDec ^ (bDec & (cDec ^ dDec))
		case 1:
			f = cDec ^ (dDec & (bDec ^ cDec))
		case 2:
			f = bDec ^ cDec ^ dDec
		case 3:
			f = cDec ^ (bDec | ^dDec)
		}

		// Select hidden words based on group
		var msg uint32
		if i < 32 {
			msg = hiddenG0[MsgSchedule[i]]
		} else {
			msg = hiddenG2[MsgSchedule[i]]
		}

		// Accumulate
		aFull := aDec + msg
		if i == 17 && aEnc >= 0 {
			aFull += OutBiases[aEnc]
		}
		tmp := aFull + f + AddConsts[i]

		// Rotate right
		tmp = rotateRight32(tmp, RorAmounts[i])

		// Add decoded b
		postAddB := tmp + bDec

		// Affine bijection encoding
		newB := postAddB - (ModConsts[i] & (postAddB << 1)) + OutBiases[i]

		// Shift state
		a, b, c, d = d, newB, b, c
		aEnc, bEnc, cEnc, dEnc = dEnc, i, bEnc, cEnc
	}

	// Decode the final a,b,c,d from their affine bijection encodings.
	// After 64 sub-rounds, each carries OutBiases[enc] that must be XOR'd off
	// before the standard MD5 accumulation step.
	if aEnc >= 0 {
		a ^= OutBiases[aEnc]
	}
	// bEnc == 63, OutBiases[63] == 0, so b is already decoded.
	if bEnc >= 0 {
		b ^= OutBiases[bEnc]
	}
	if cEnc >= 0 {
		c ^= OutBiases[cEnc]
	}
	if dEnc >= 0 {
		d ^= OutBiases[dEnc]
	}

	// Standard MD5 accumulation
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
}

// rotateRight32 performs a 32-bit right rotation.
func rotateRight32(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

// roundA_bswap byte-swaps count uint32 words starting at the given offset in state.
func roundA_bswap(state *HashState, offset, count int) {
	for i := 0; i < count; i++ {
		idx := offset + i*4
		if idx+4 <= len(state.Mem) {
			v := binary.LittleEndian.Uint32(state.Mem[idx:])
			v = bswap32(v)
			binary.LittleEndian.PutUint32(state.Mem[idx:], v)
		}
	}
}

// bswap32 reverses the byte order of a 32-bit value.
func bswap32(v uint32) uint32 {
	return (v>>24)&0xFF | (v>>8)&0xFF00 | (v<<8)&0xFF0000 | (v<<24)&0xFF000000
}

// roundB_constExpand XOR-mixes 15 T-box constants into the state for the given round.
func roundB_constExpand(state *HashState, round int) {
	tbox := RoundBTbox[round]
	for i := 0; i < 15; i++ {
		idx := RoundBTargetOffset + i*4
		if idx+4 <= len(state.Mem) {
			v := binary.LittleEndian.Uint32(state.Mem[idx:])
			v ^= tbox[i]
			binary.LittleEndian.PutUint32(state.Mem[idx:], v)
		}
	}
}

// readState reads the 4 MD5 state words from the state memory.
func readState(state *HashState, md5 *[4]uint32, round int) {
	// The msg area pointer varies per round (captured during extraction)
	offset := RoundMsgAreaOffset[round]
	for w := 0; w < 4; w++ {
		md5[w] = binary.LittleEndian.Uint32(state.Mem[offset+w*4:])
	}
}

// writeState writes the 4 MD5 state words back to state memory.
func writeState(state *HashState, md5 *[4]uint32, round int) {
	offset := RoundMsgAreaOffset[round]
	for w := 0; w < 4; w++ {
		binary.LittleEndian.PutUint32(state.Mem[offset+w*4:], md5[w])
	}
}

// readHiddenWords reads the 16 hidden words for both groups.
func readHiddenWords(_ *HashState, hiddenG0, hiddenG2 *[16]uint32, round int) {
	// The hidden words are payload-independent constants that evolve through
	// a NEON permutation across rounds. They derive from stack frame metadata
	// (transformed pointers, magic values like 0xdeadbeef) rather than payload.
	//
	// G0 is used for sub-rounds 0-31 (groups 0-1, F and G functions).
	// G2 is used for sub-rounds 32-63 (groups 2-3, H and I functions).
	// The NEON permutation within each RoundC transforms G0 into G2 mid-round,
	// and the result carries forward as G0 for the next round.
	*hiddenG0 = HiddenWordsG0[round]
	*hiddenG2 = HiddenWordsG2[round]
}

// HashState holds the Phase 2 hash computation state.
// This is the memory region from Phase 1 output, indexed by SP-relative offsets.
type HashState struct {
	Mem []byte // SP-relative memory region (~10KB)
}

// Constants for state layout (SP-relative byte offsets).
// These will be populated by the extraction test.
const (
	HiddenWordsOffset  = 0    // SP+0: 16 hidden words (64 bytes)
	RoundAShortOffset  = 3184 // SP+3184: bswap target (short, 4 words)
	RoundAShortCount   = 4    // 4 words for short bswap
	RoundALongOffset   = 3208 // SP+3208: bswap target (long, 14 words)
	RoundALongCount    = 14   // 14 words for long bswap
	RoundBTargetOffset = 3056 // SP+3056: T-box target area (15 words)
)

// round8InitialState is the constant initial MD5 state for rounds 8 and 19.
// These rounds use msg area offset 3568 instead of the normal 3360.
// The bytecode's inter-round code writes this constant before each of those
// rounds. Verified payload-independent across payloads 0x00, 0x01, 0x42, 0xFF.
var round8InitialState = [4]uint32{0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216}

// RoundMsgAreaOffset maps round number to SP-relative byte offset of the msg area.
// Base msg area: 0x707fed70 (SP+0xD20 = SP+3360)
// Three non-default rounds:
//
//	Round 8: 0x707fee40 (SP+0xDF0 = SP+3568, +208 from base)
//	Round 9: 0x707fed18 (SP+0xCC8 = SP+3272, -88 from base)
//	Round 19: 0x707fee40 (SP+0xDF0 = SP+3568, +208 from base)
//
// Verified by preamble-split parity test against ARM64 emulator trace.
var RoundMsgAreaOffset = [20]int{
	3360, 3360, 3360, 3360, // rounds 0-3
	3360, 3360, 3360, 3360, // rounds 4-7
	3568, 3272, 3360, 3360, // rounds 8-11 (round 8 = +208, round 9 = -88)
	3360, 3360, 3360, 3360, // rounds 12-15
	3360, 3360, 3360, 3568, // rounds 16-19 (round 19 = +208)
}

// RoundBTbox contains the 15 T-box XOR constants for each of the 20 rounds.
// These are XOR'd into state at SP+3056..SP+3116 during the RoundB constant
// expansion step. Most rounds have all-zero T-box values (RoundB is effectively
// a no-op), with non-zero entries only at rounds 8 and 10.
// Extracted by instrumenting Phase 2 execution on ARM64 trace.
var RoundBTbox = [20][15]uint32{
	{}, // Round 0
	{}, // Round 1
	{}, // Round 2
	{}, // Round 3
	{}, // Round 4
	{}, // Round 5
	{}, // Round 6
	{}, // Round 7
	{ // Round 8 (4 non-zero entries)
		0x00000000, 0x00000000, 0x00017068, 0x00000000, 0x00000000,
		0x00000000, 0x00017068, 0x00000000, 0x00000000, 0x00000000,
		0x00017068, 0x00000000, 0x00000000, 0x00000000, 0x2616e38c,
	},
	{}, // Round 9
	{ // Round 10 (1 non-zero entry)
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x2616e38c,
	},
	{}, // Round 11
	{}, // Round 12
	{}, // Round 13
	{}, // Round 14
	{}, // Round 15
	{}, // Round 16
	{}, // Round 17
	{}, // Round 18
	{}, // Round 19
}
