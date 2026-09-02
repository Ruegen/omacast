// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "math/bits"

// The "affine bijection" white-box encoding in RoundC_WBMD5_Permuted is
// algebraically the identity. Two facts make it collapse:
//
//  1. ModConsts[i] == 2*OutBiases[i] for all 64 i.
//  2. For all x, c:  x - (2c & (x<<1)) + c  ==  x ^ c   (mod 2^32),
//     because 2c & 2x == 2(c&x) and x + c - 2(x&c) is the definition of x ^ c.
//
// So the encode step `postAddB - (ModConsts[i] & (postAddB<<1)) + OutBiases[i]`
// is exactly `postAddB ^ OutBiases[i]`, and the XOR-decode at the top of the
// next sub-round removes the same constant. Every encode/decode pair cancels.
//
// What remains is plain MD5 over the hidden words, with exactly two places
// where the encoding is still observable:
//
//   - sub-round 17 adds OutBiases[aEncAt17] to the accumulator (the "round 17
//     anomaly"), which folds into a per-sub-round constant table; and
//   - the Group 1->2 shuffle at sub-round 32 consumes the *encoded* state
//     words, so they must be re-encoded at that one point.
//
// RoundC_MD5Plain is bit-exact with RoundC_WBMD5_Permuted; see
// TestRoundCPlainEquivalence.

// encoding-tracker indices at the START of sub-round i, derived from the
// rotation `aEnc,bEnc,cEnc,dEnc = dEnc, i, bEnc, cEnc`:
//
//	aEnc = i-4   bEnc = i-1   cEnc = i-2   dEnc = i-3      (negative => raw)
const (
	anomalySubRound = 17 // sub-round with the extra OutBias term
	anomalyEncRound = anomalySubRound - 4
	shuffleSubRound = 32 // Group 1->2 boundary, consumes encoded state
)

// plainAddConsts folds the sub-round-17 anomaly into the constant table so the
// inner loop is branch-free apart from the F-function selector.
var plainAddConsts = func() [64]uint32 {
	k := AddConsts
	k[anomalySubRound] += OutBiases[anomalyEncRound]
	return k
}()

// RoundC_MD5Plain computes the same result as RoundC_WBMD5_Permuted with the
// white-box encoding layer removed. hiddenG2 == nil triggers the same
// state-dependent ShuffleHiddenG2 at sub-round 32.
// RoundC_MD5PlainReference is the sub-round loop as first written, kept as the
// oracle TestRoundCUnrolledMatchesReference checks the unrolled form against.
func RoundC_MD5PlainReference(state *[4]uint32, hiddenG0, hiddenG2 *[16]uint32) {
	a, b, c, d := state[0], state[1], state[2], state[3]

	// Declared up front so the shuffle result does not escape to the heap.
	var g2Buf [16]uint32

	for i := 0; i < 64; i++ {
		if i == shuffleSubRound && hiddenG2 == nil {
			// The shuffle reads the ENCODED state words. At i==32 the
			// encoding rounds are a:28 b:31 c:30 d:29.
			g2Buf = ShuffleHiddenG2(hiddenG0,
				a^OutBiases[shuffleSubRound-4],
				b^OutBiases[shuffleSubRound-1],
				c^OutBiases[shuffleSubRound-2],
				d^OutBiases[shuffleSubRound-3])
			hiddenG2 = &g2Buf
		}

		var f uint32
		switch i >> 4 {
		case 0:
			f = d ^ (b & (c ^ d))
		case 1:
			f = c ^ (d & (b ^ c))
		case 2:
			f = b ^ c ^ d
		case 3:
			f = c ^ (b | ^d)
		}

		msg := hiddenG0[MsgSchedule[i]]
		if i >= 32 {
			msg = hiddenG2[MsgSchedule[i]]
		}

		tmp := a + msg + f + plainAddConsts[i]
		tmp = bits.RotateLeft32(tmp, -int(RorAmounts[i]))

		a, b, c, d = d, tmp+b, b, c
	}

	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
}
