// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import "sync"

// wbaesTypeIOrder contains the Type-I table index for each (round, position).
// Rounds 1-9: each position maps to a unique table from TypeI[0..143].
// Round 10: uses TypeI[144..159].
var wbaesTypeIOrder = [10][16]int{
	// Round 1
	{32, 132, 88, 44, 141, 41, 85, 129, 82, 138, 38, 94, 35, 135, 91, 47},
	// Round 2
	{64, 20, 120, 76, 29, 73, 117, 17, 114, 26, 70, 126, 67, 23, 123, 79},
	// Round 3
	{96, 52, 8, 108, 61, 105, 5, 49, 2, 58, 102, 14, 99, 55, 11, 111},
	// Round 4
	{128, 84, 40, 140, 93, 137, 37, 81, 34, 90, 134, 46, 131, 87, 43, 143},
	// Round 5
	{16, 116, 72, 28, 125, 25, 69, 113, 66, 122, 22, 78, 19, 119, 75, 31},
	// Round 6
	{48, 4, 104, 60, 13, 57, 101, 1, 98, 10, 54, 110, 51, 7, 107, 63},
	// Round 7
	{80, 36, 136, 92, 45, 89, 133, 33, 130, 42, 86, 142, 83, 39, 139, 95},
	// Round 8
	{112, 68, 24, 124, 77, 121, 21, 65, 18, 74, 118, 30, 115, 71, 27, 127},
	// Round 9
	{0, 100, 56, 12, 109, 9, 53, 97, 50, 106, 6, 62, 3, 103, 59, 15},
	// Round 10 (no MixColumns)
	{144, 148, 152, 156, 157, 153, 149, 145, 146, 154, 150, 158, 147, 151, 155, 159},
}

// wbaesMixingSigma is the mixing permutation σ applied between TypeI outputs and
// TypeII inputs. Discovered via brute-force column matching across 4 single-byte
// emulator traces. Round 1 uses identity (no mixing). Rounds 2-9 use this σ.
//
// The mixing bijection maps: TypeII_in[seq(i)] = TypeI_out[σ(i)] ⊕ constant
// Cycles: (0)(5)(1,6,11,4)(2,9,13,7,12,3,15,14,10,8)  [+ identity at 0,5]
var wbaesMixingSigma = [16]int{0, 6, 9, 15, 1, 5, 11, 12, 2, 4, 8, 13, 3, 7, 10, 14}

// σ⁻¹: inverse of σ, maps position back to original state index
// Proven: typeIOut[i] = TypeI[order[i]][state[σ⁻¹(i)]]
var wbaesMixingSigmaInv = [16]int{0, 4, 8, 12, 9, 5, 1, 13, 10, 2, 14, 6, 7, 11, 15, 3}

// wbaesMixingConsts holds per-round mixing constants.
// Combined formula: sub[i] = TypeI[order[σ(i)]][state[i]] ⊕ mixConst[i]
var wbaesMixingConsts [9][16]byte

// wbaesMixingConstsOnce guards the one-time calibration. It was a plain bool,
// which raced when two exchanges ran concurrently.
var wbaesMixingConstsOnce sync.Once

// wbaesInitMixingConsts precomputes the mixing constants for all 9 rounds.
// Must be called before wbaesBlockTbox or wbaesBlockCore is used with non-zero inputs.
func wbaesInitMixingConsts() {
	wbaesMixingConstsOnce.Do(buildMixingConsts)
}

func buildMixingConsts() {
	// Zero-input calibration: state = all zeros
	var zeroState [16]byte
	for rnd := 0; rnd < 9; rnd++ {
		order := &wbaesTypeIOrder[rnd]
		xorC := &wbaesXORConsts[rnd]

		// Compute zero TypeI outputs.
		// Round 1: zeroState is all-zeros so σ⁻¹ doesn't matter.
		// Rounds 2+: state enters naturally (no σ⁻¹ between rounds).
		var t0 [16]byte
		for i := 0; i < 16; i++ {
			t0[i] = wbaesTypeI[order[i]][zeroState[i]]
		}
		var subZero [16]byte
		for i := 0; i < 16; i++ {
			subZero[i] = t0[i] ^ xorC[i]
		}

		// Compute mixing constants using combined formula:
		// sub[i] = TypeI[order[σ(i)]][state[i]] ⊕ mixConst[i]
		// At zero input: subZero[i] = t0[σ(i)] ⊕ mixConst[i]
		// → mixConst[i] = t0[σ(i)] ⊕ subZero[i]
		for i := 0; i < 16; i++ {
			wbaesMixingConsts[rnd][i] = t0[wbaesMixingSigma[i]] ^ subZero[i]
		}

		// Advance zero state through this round (for next round's calibration)
		var cols [4]uint32
		for col := 0; col < 4; col++ {
			p := &wbaesShiftRowsCols[col]
			cols[col] = wbaesTypeII[0][subZero[p[0]]] ^
				wbaesTypeII[1][subZero[p[1]]] ^
				wbaesTypeII[2][subZero[p[2]]] ^
				wbaesTypeII[3][subZero[p[3]]]
		}
		zeroState[0] = byte(cols[0])
		zeroState[1] = byte(cols[1])
		zeroState[2] = byte(cols[2])
		zeroState[3] = byte(cols[3])
		zeroState[4] = byte(cols[2] >> 8)
		zeroState[5] = byte(cols[1] >> 8)
		zeroState[6] = byte(cols[0] >> 8)
		zeroState[7] = byte(cols[3] >> 8)
		zeroState[8] = byte(cols[2] >> 16)
		zeroState[9] = byte(cols[0] >> 16)
		zeroState[10] = byte(cols[3] >> 16)
		zeroState[11] = byte(cols[1] >> 16)
		zeroState[12] = byte(cols[1] >> 24)
		zeroState[13] = byte(cols[2] >> 24)
		zeroState[14] = byte(cols[3] >> 24)
		zeroState[15] = byte(cols[0] >> 24)
	}
	buildFusedTypeI()
}

// wbaesBlockTbox computes one WB-AES block using extracted T-box tables.
// Input: 16 bytes of plaintext.
// Output: 16 bytes of WB-AES ciphertext (before fold XOR).
//
// Algorithm per round 1-9:
//  1. Apply 16 Type-I lookups (SubBytes through encoded bijections)
//  2. Apply mixing permutation σ to map TypeI outputs → TypeII inputs
//  3. Apply 4×4 Type-II lookups (SubBytes+MixColumns combined), XOR results per column
//  4. Extract 4 bytes from each column word → next round state (ShiftRows implicit in table ordering)
//
// Round 10: 16 Type-I lookups only (no MixColumns), output is final.
func wbaesBlockTbox(input [16]byte) [16]byte {
	wbaesInitMixingConsts()

	// Round 1: input bytes are loaded with σ⁻¹ permutation.
	// Rounds 2-9: state bytes enter naturally from byte extraction.
	var state [16]byte
	for i := 0; i < 16; i++ {
		state[i] = input[wbaesMixingSigmaInv[i]]
	}

	// Rounds 1-9: TypeI → mixing permutation σ → TypeII(MixColumns) → byte extraction
	for rnd := 0; rnd < 9; rnd++ {
		order := &wbaesTypeIOrder[rnd]
		mixC := &wbaesMixingConsts[rnd]

		// Step 1: TypeI lookups (state enters naturally)
		var typeIOut [16]byte
		for i := 0; i < 16; i++ {
			typeIOut[i] = wbaesTypeI[order[i]][state[i]]
		}

		// Step 2: σ permutes TypeI outputs → sub values
		// sub[i] = typeIOut[σ(i)] ⊕ mixConst[i]
		var sub [16]byte
		for i := 0; i < 16; i++ {
			sub[i] = typeIOut[wbaesMixingSigma[i]] ^ mixC[i]
		}

		// Step 3: Apply ShiftRows + Type-II lookups (MixColumns) + column XOR
		var cols [4]uint32
		for col := 0; col < 4; col++ {
			p := &wbaesShiftRowsCols[col]
			cols[col] = wbaesTypeII[0][sub[p[0]]] ^
				wbaesTypeII[1][sub[p[1]]] ^
				wbaesTypeII[2][sub[p[2]]] ^
				wbaesTypeII[3][sub[p[3]]]
		}

		// Step 4: Extract bytes from column words → next state
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

	// Round 10: Type-I only (SubBytes without MixColumns)
	// Apply per-byte output decoding to convert encoded output → actual GP values
	// Output decoding maps raw[i] → gp[gpBufferPerm[i]], so we reorder
	// to produce output in GP buffer byte order.
	order := &wbaesTypeIOrder[9]
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[gpBufferPerm[i]] = wbaesOutputDec[i][wbaesTypeI[order[i]][state[i]]]
	}
	return out
}
