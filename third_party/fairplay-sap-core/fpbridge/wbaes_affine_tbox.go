// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

// gfMulAES performs multiplication in GF(2^8) using the AES irreducible polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11B). The reduction constant 0x1B is the low byte.
func gfMulAES(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1B
		}
		b >>= 1
	}
	return p
}

// gfInvAES computes the multiplicative inverse in GF(2^8) using Fermat's
// little theorem: a^{-1} = a^{254} in GF(2^8).
func gfInvAES(a byte) byte {
	if a == 0 {
		return 0
	}
	result := byte(1)
	base := a
	n := 254
	for n > 0 {
		if n&1 == 1 {
			result = gfMulAES(result, base)
		}
		base = gfMulAES(base, base)
		n >>= 1
	}
	return result
}

// ---------------------------------------------------------------------------
// Copied from bge_tbox_native_test.go — these were test-only and are needed
// by the production affine T-box.
// ---------------------------------------------------------------------------

// wbaesTypeIOrderAffine contains the Type-I table index for each (round, position).
// Rounds 1-9: each position maps to a unique table from TypeI[0..143].
// Round 10: uses TypeI[144..159].
var wbaesTypeIOrderAffine = [10][16]int{
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

// wbaesMixingSigmaAffine is the mixing permutation σ applied between TypeI outputs
// and TypeII inputs. Round 1 uses identity (no mixing). Rounds 2-9 use this σ.
var wbaesMixingSigmaAffine = [16]int{0, 6, 9, 15, 1, 5, 11, 12, 2, 4, 8, 13, 3, 7, 10, 14}

// ---------------------------------------------------------------------------
// Affine mixing bijection model
// ---------------------------------------------------------------------------

// wbaesAffineParam holds the per-position affine mixing parameters for one byte lane.
//
//	Sigma: index into the TypeI output array (the permutation σ(i))
//	A:     GF(2^8) multiplicative factor
//	B:     GF(2^8) additive constant (XOR)
//
// The affine mixing bijection computes:
//
//	sub[i] = gfMulAES(A, TypeI_out[Sigma]) ^ B
type wbaesAffineParam struct {
	Sigma int
	A, B  byte
}

// wbaesAffineParams holds the affine mixing parameters for rounds 1-9 (indices 0-8),
// with 16 byte positions per round. These replace the old wbaesMixingSigma + wbaesMixingConsts.
//
// To be populated by wbaesInitAffineParams once actual parameter values are recovered.
var wbaesAffineParams [9][16]wbaesAffineParam

// wbaesAffineParamsReady is set after wbaesInitAffineParams completes.
var wbaesAffineParamsReady bool

// wbaesInitAffineParams precomputes the affine mixing parameters for all 9 rounds.
// Must be called before wbaesBlockTboxAffine is used.
//
// PLACEHOLDER: This function currently initialises the parameters to replicate the
// existing XOR-only model (A=1, B=mixConst) so that the affine T-box produces
// identical output to the original wbaesBlockTbox. Replace the body once the true
// GF(2^8) affine parameters have been recovered.
func wbaesInitAffineParams() {
	if wbaesAffineParamsReady {
		return
	}

	// --- Replicate the wbaesInitMixingConsts logic inline ---
	// Zero-input calibration: state = all zeros
	var zeroState [16]byte
	var mixConsts [9][16]byte

	for rnd := 0; rnd < 9; rnd++ {
		order := &wbaesTypeIOrderAffine[rnd]
		xorC := &wbaesXORConsts[rnd]

		// Compute zero TypeI outputs and naive sub values
		var t0 [16]byte
		for i := 0; i < 16; i++ {
			t0[i] = wbaesTypeI[order[i]][zeroState[i]]
		}
		var subZero [16]byte
		for i := 0; i < 16; i++ {
			subZero[i] = t0[i] ^ xorC[i]
		}

		// Compute mixing constants: mixConst[i] = t0[σ(i)] ⊕ subZero[i]
		for i := 0; i < 16; i++ {
			si := i // identity for round 1
			if rnd > 0 {
				si = wbaesMixingSigmaAffine[i]
			}
			mixConsts[rnd][i] = t0[si] ^ subZero[i]
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

	// --- Populate affine params using XOR-only degenerate model ---
	for rnd := 0; rnd < 9; rnd++ {
		for i := 0; i < 16; i++ {
			si := i
			if rnd > 0 {
				si = wbaesMixingSigmaAffine[i]
			}
			// A = 1 makes gfMulAES(1, x) = x, so the affine model degenerates to XOR-only.
			wbaesAffineParams[rnd][i] = wbaesAffineParam{
				Sigma: si,
				A:     0x01,
				B:     mixConsts[rnd][i],
			}
		}
	}

	wbaesAffineParamsReady = true
}

// wbaesBlockTboxAffine computes one WB-AES block using extracted T-box tables with
// the full GF(2^8) affine mixing bijection model.
//
// Input: 16 bytes of plaintext.
// Output: 16 bytes of WB-AES ciphertext (before fold XOR).
//
// Algorithm per round 1-9:
//  1. Apply 16 Type-I lookups (SubBytes through encoded bijections)
//  2. Apply per-position affine mixing:
//     sub[i] = gfMulAES(a[i], TypeI_out[σ(i)]) ^ b[i]
//  3. Apply 4×4 Type-II lookups (SubBytes+MixColumns combined), XOR results per column
//  4. Extract 4 bytes from each column word → next round state
//     (ShiftRows implicit in wbaesShiftRowsCols ordering)
//
// Round 10: 16 Type-I lookups only (no MixColumns), output decoded via wbaesOutputDec.
func wbaesBlockTboxAffine(input [16]byte) [16]byte {
	wbaesInitAffineParams()

	var state [16]byte
	copy(state[:], input[:])

	// Rounds 1-9: TypeI → affine mixing → TypeII(MixColumns) → byte extraction
	for rnd := 0; rnd < 9; rnd++ {
		order := &wbaesTypeIOrderAffine[rnd]
		params := &wbaesAffineParams[rnd]

		// Step 1: Apply Type-I lookups to get raw outputs
		var typeIOut [16]byte
		for i := 0; i < 16; i++ {
			typeIOut[i] = wbaesTypeI[order[i]][state[i]]
		}

		// Step 2: Apply affine mixing bijection → sub values
		// sub[i] = gfMulAES(a[i], TypeI_out[σ(i)]) ^ b[i]
		var sub [16]byte
		for i := 0; i < 16; i++ {
			p := &params[i]
			sub[i] = gfMulAES(p.A, typeIOut[p.Sigma]) ^ p.B
		}

		// Step 3: Apply ShiftRows + Type-II lookups (MixColumns) + column XOR
		var cols [4]uint32
		for col := 0; col < 4; col++ {
			sr := &wbaesShiftRowsCols[col]
			cols[col] = wbaesTypeII[0][sub[sr[0]]] ^
				wbaesTypeII[1][sub[sr[1]]] ^
				wbaesTypeII[2][sub[sr[2]]] ^
				wbaesTypeII[3][sub[sr[3]]]
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
	order := &wbaesTypeIOrderAffine[9]
	var out [16]byte
	for i := 0; i < 16; i++ {
		out[i] = wbaesOutputDec[i][wbaesTypeI[order[i]][state[i]]]
	}
	return out
}
