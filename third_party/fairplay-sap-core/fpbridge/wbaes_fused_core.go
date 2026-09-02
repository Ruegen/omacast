// SPDX-License-Identifier: BlueOak-1.0.0

package fpbridge

import "encoding/binary"

// wbaesBlockCore keeps the state in the mixing permutation's own order rather
// than in AES order. Writing stateP[i] = state[σ(i)] does three things at once:
//
//   - the per-round read becomes stateP[i] instead of state[σ(i)], so the σ
//     lookup and its dependent load disappear from the inner loop;
//   - the end-of-round shuffle, sixteen scattered byte extracts in AES order,
//     becomes four little-endian word writes — σ was exactly what made that
//     shuffle look scrambled;
//   - the input permutation vanishes, because state[σ(i)] = input[σ⁻¹(σ(i))]
//     = input[i], so the block starts as a plain copy.
//
// Only round 10 pays for it, reading through σ⁻¹ once instead of σ nine times.
func wbaesBlockCore(input [16]byte) [16]byte {
	wbaesInitMixingConsts()

	state := input

	for rnd := 0; rnd < 9; rnd++ {
		fused := &wbaesFusedI[rnd]

		// One pass instead of three: the Type-I lookup, the mixing permutation
		// and the constant XOR are all folded into fused. See wbaes_fused.go.
		var sub [16]byte
		for i := 0; i < 16; i++ {
			sub[i] = fused[i][state[i]]
		}
		for col := 0; col < 4; col++ {
			p := &wbaesShiftRowsCols[col]
			binary.LittleEndian.PutUint32(state[col*4:], wbaesTypeII[0][sub[p[0]]]^
				wbaesTypeII[1][sub[p[1]]]^
				wbaesTypeII[2][sub[p[2]]]^
				wbaesTypeII[3][sub[p[3]]])
		}
	}

	// Round 10: TypeI only (no MixColumns, no output decoding yet). The state is
	// still permuted, so this is the one place σ⁻¹ is paid.
	order9 := &wbaesTypeIOrder[9]
	var raw [16]byte
	for i := 0; i < 16; i++ {
		raw[i] = wbaesTypeI[order9[i]][state[wbaesMixingSigmaInv[i]]]
	}
	return raw
}
