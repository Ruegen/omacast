// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import (
	"encoding/binary"
)

// Span7Offset is the SP-relative byte offset of the span7 output region.
// span7 is 20 bytes: the final Phase 2 hash output.
const Span7Offset = 13584 // SP+0x3510

// tailByteSubstXOR is the 4-byte XOR constant applied to span7[0:4] after
// the XOR fold. Bytes: [0x67, 0xBC, 0x54, 0xC0].
// Verified constant across all tested payloads (0x00, 0x01, 0x42, 0xFF).
const TailByteSubstXOR uint32 = 0xC054BC67

// foldRoundOrder maps fold index (0..8) to round number.
// The XOR fold uses bswapped outputs from rounds 0-7 and 10 (skipping 8, 9, 11-19).
// Rounds 8 and 19 use a different msg area offset (3568 vs 3360);
// rounds 11-19 repeat the same values as 0-7 (hash cycles).
var FoldRoundOrder = [9]int{0, 1, 2, 3, 4, 5, 6, 7, 10}

// gpFoldConstants are the GP-mixing XOR constants applied during the fold.
// fold_val[i] = bswap(roundOutput[foldRoundOrder[i]]) XOR gpFoldConstants[i]
//
// These are payload-independent constants extracted from the inter-round
// linked-list traversal code. They combine transformed pointer metadata,
// magic values, and encoded GP register data from the ARM64 binary's
// data section.
//
// Extracted by: GP[i] = fold_delta[i] XOR bswap(round_raw[i]) for reference payload.
// Verified constant across payloads 0x00, 0x01, 0x42, 0xFF.
var GpFoldConstants = [9][4]uint32{
	{0x1f35dcbd, 0x0620944b, 0x6b2ebcff, 0x4c04404b}, // R0
	{0x12d93967, 0xa8497349, 0x38bfbad7, 0x6b3cfc83}, // R1
	{0xc0c6f215, 0xeb86897b, 0xf3e98781, 0x7d667a8e}, // R2
	{0x5deb0b4a, 0x25ae3c64, 0x56dbfa68, 0x63eaef7f}, // R3
	{0x4db1f4ee, 0x7d8bca77, 0xce8ffa1e, 0x671db270}, // R4
	{0x742116f8, 0xac346a48, 0x0b6a8a30, 0x873a97ba}, // R5
	{0x363c61ac, 0x5291fc79, 0xb388e73d, 0x24f84651}, // R6
	{0x15f85e7e, 0x99b15da3, 0xa187359d, 0x2ff544a2}, // R7
	{0x6ca729d8, 0x80292920, 0xb2d8299f, 0x623b2de6}, // R10
}

// FinalizeSpan7 assembles the 20-byte span7 output from the captured round outputs.
//
// The span7 structure is:
//
//	span7[0:4]  = byte_subst(xor_fold(bswap(R8) ⊕ Σ(bswap(Ri) ⊕ GP[i])))[0:4]
//	span7[4:20] = R19_raw (direct copy, 16 bytes)
//
// Where:
//   - R8, R19 are the raw RoundC outputs for rounds 8 and 19
//   - The XOR fold accumulates 9 values from rounds {0,1,...,7,10}
//   - Each fold value is bswap(Ri_raw) XOR gpFoldConstants[i]
//   - byte_subst XORs the first 4 bytes with tailByteSubstXOR
//
// This replaces ~2641 ARM64 tail instructions with a direct computation.
func FinalizeSpan7(state *HashState, roundOutputs *[20][4]uint32) {
	// Initialize fold accumulator with bswapped R8 raw output
	var acc [4]uint32
	for w := 0; w < 4; w++ {
		acc[w] = bswap32(roundOutputs[8][w])
	}

	// XOR fold: accumulate 9 fold values from rounds {0,1,...,7,10}
	for i := 0; i < 9; i++ {
		roundIdx := FoldRoundOrder[i]
		for w := 0; w < 4; w++ {
			foldVal := bswap32(roundOutputs[roundIdx][w]) ^ GpFoldConstants[i][w]
			acc[w] ^= foldVal
		}
	}

	// Apply 4-byte substitution XOR to the first word
	acc[0] ^= TailByteSubstXOR

	// Write span7[0:4] from the fold result
	if Span7Offset+20 <= len(state.Mem) {
		binary.LittleEndian.PutUint32(state.Mem[Span7Offset:], acc[0])

		// Write span7[4:20] from R19 raw output (direct copy, 16 bytes)
		for w := 0; w < 4; w++ {
			binary.LittleEndian.PutUint32(state.Mem[Span7Offset+4+w*4:], roundOutputs[19][w])
		}
	}
}
