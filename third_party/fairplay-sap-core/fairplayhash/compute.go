// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"encoding/binary"
)

// ComputeHash computes the Phase 2 ARX hash.
// See hash.go for the full implementation.
//
// NOTE: ComputeHash currently reads the initial MD5 state from
// RoundMsgAreaOffset[round] in state.Mem. After Phase 1, these locations
// are all-zero because the Phase 1 output lives in registers (x, sp, vreg),
// NOT in memory. The register→memory mapping must be performed before
// calling ComputeHash.
//
// For correct Phase 2 execution, use nativeHashPhase2() in the fpemu
// package, which takes registers as input.
//
// The register→memory mapping is being researched. Once complete,
// ComputeM3Setup() will populate the msg area from register state,
// allowing ComputeHash to produce correct output.

// ComputeM3Setup populates the HashState memory from Phase 1 register output.
// This must be called before ComputeHash to set up the initial MD5 state words.
//
// Parameters:
//   - state: HashState with Mem sliced to start at SP (SP-relative offsets)
//   - initialMD5: the 4 initial MD5 state words extracted from registers
//
// The mapping from registers to initialMD5 is:
//   - nativeHashPhase2 reads from mem[x[9]+0x10..x[9]+0x28] after
//     performing NEON operations (EOR, SHL, AND, ADD) with vreg[0..4]
//   - The resulting 4 uint32 words are written to RoundMsgAreaOffset[0]
//
// TODO: Implement the full register→MD5 state extraction.
func ComputeM3Setup(state *HashState, initialMD5 [4]uint32) {
	// Write initial MD5 state to round 0 msg area
	// This is where readState() will read from
	offset := RoundMsgAreaOffset[0]
	for w := 0; w < 4; w++ {
		binary.LittleEndian.PutUint32(state.Mem[offset+w*4:], initialMD5[w])
	}
}

// HashOutputSize is the size of the Phase 2 hash output in bytes.
const HashOutputSize = 20
