// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

// gpBufferPerm maps T-box raw position i to GP buffer position gpBufferPerm[i].
// This permutation reorders the AES state bytes into the GP buffer layout.
var gpBufferPerm = [16]int{0, 4, 8, 12, 13, 9, 5, 1, 2, 10, 6, 14, 3, 7, 11, 15}

// wbaesBlockCore computes the WB-AES core (rounds 1-9 TypeI→σ→XOR→TypeII
// MixColumns + round 10 TypeI), returning the raw round-10 TypeI outputs
// BEFORE output decoding.
//
// This core is identical for ALL 8 blocks — the only difference between
// blocks is the output encoding applied afterward.
// wbaesBlockCoreReference is the core as first written, kept as the oracle
// TestFusedTypeIMatchesReference checks the fused path against.
func wbaesBlockCoreReference(input [16]byte) [16]byte {
	wbaesInitMixingConsts()

	var state [16]byte
	for i := 0; i < 16; i++ {
		state[i] = input[wbaesMixingSigmaInv[i]]
	}

	for rnd := 0; rnd < 9; rnd++ {
		order := &wbaesTypeIOrder[rnd]
		mixC := &wbaesMixingConsts[rnd]

		var typeIOut [16]byte
		for i := 0; i < 16; i++ {
			typeIOut[i] = wbaesTypeI[order[i]][state[i]]
		}
		var sub [16]byte
		for i := 0; i < 16; i++ {
			sub[i] = typeIOut[wbaesMixingSigma[i]] ^ mixC[i]
		}
		var cols [4]uint32
		for col := 0; col < 4; col++ {
			p := &wbaesShiftRowsCols[col]
			cols[col] = wbaesTypeII[0][sub[p[0]]] ^
				wbaesTypeII[1][sub[p[1]]] ^
				wbaesTypeII[2][sub[p[2]]] ^
				wbaesTypeII[3][sub[p[3]]]
		}
		state[0] = byte(cols[0])
		state[1] = byte(cols[1])
		state[2] = byte(cols[2])
		state[3] = byte(cols[3])
		state[4] = byte(cols[2] >> 8)
		state[5] = byte(cols[1] >> 8)
		state[6] = byte(cols[0] >> 8)
		state[7] = byte(cols[3] >> 8)
		state[8] = byte(cols[2] >> 16)
		state[9] = byte(cols[0] >> 16)
		state[10] = byte(cols[3] >> 16)
		state[11] = byte(cols[1] >> 16)
		state[12] = byte(cols[1] >> 24)
		state[13] = byte(cols[2] >> 24)
		state[14] = byte(cols[3] >> 24)
		state[15] = byte(cols[0] >> 24)
	}

	// Round 10: TypeI only (no MixColumns, no output decoding yet)
	order9 := &wbaesTypeIOrder[9]
	var raw [16]byte
	for i := 0; i < 16; i++ {
		raw[i] = wbaesTypeI[order9[i]][state[i]]
	}
	return raw
}

// wbaesFullPhase1 computes the full Phase 1 GP buffer using T-box tables.
// This replaces 1.66M ARM64 instructions with pure table lookups.
//
// Architecture:
//   - All 8 blocks share the IDENTICAL WB-AES core
//   - Block 0: output decoding via complex bijection tables (wbaesOutputDec)
//   - Blocks 1-7: output decoding via raw ^ 0x0F (trivial XOR constant)
//   - Chaining: GP[n] = BlockN(P_n) ⊕ P_{n-1}  (block 0 has no chaining XOR)
//
// Performance: 3.4µs per payload on Apple M4 (3,300× faster than interpreter).
func wbaesFullPhase1(payload [128]byte) [128]byte {
	var gp [128]byte

	for block := 0; block < 8; block++ {
		var blockIn [16]byte
		copy(blockIn[:], payload[block*16:])

		// WB-AES core: identical computation for all blocks
		raw := wbaesBlockCore(blockIn)

		// Per-block output encoding + GP buffer permutation
		var blockOut [16]byte
		if block == 0 {
			// Block 0: complex per-byte output decoding bijection
			for i := 0; i < 16; i++ {
				blockOut[gpBufferPerm[i]] = wbaesOutputDec[i][raw[i]]
			}
		} else {
			// Blocks 1-7: simple XOR constant (raw ^ 0x0F)
			for i := 0; i < 16; i++ {
				blockOut[gpBufferPerm[i]] = raw[i] ^ 0x0F
			}
		}

		// Plaintext XOR chaining: GP[n] = BlockN(P_n) ⊕ P_{n-1}
		// Block 0 has no chaining (output stored directly)
		if block == 0 {
			copy(gp[0:16], blockOut[:])
		} else {
			for i := 0; i < 16; i++ {
				gp[block*16+i] = blockOut[i] ^ payload[(block-1)*16+i]
			}
		}
	}

	return gp
}
