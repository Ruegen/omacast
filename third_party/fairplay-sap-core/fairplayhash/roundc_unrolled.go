// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "math/bits"

// RoundC_MD5Plain is the sub-round loop with the state rotation removed.
//
// Each sub-round ends with a, b, c, d = d, tmp+b, b, c — four moves that exist
// only to renumber the registers. Unrolling by four lets the renumbering happen
// in the naming instead: after four steps the roles have come back around, so
// each step computes exactly one new value and nothing is shuffled. Written out
// from (a, b, c, d):
//
//	b1 = b  + ror(a + m0 + F(b,  c,  d ) + k0)
//	b2 = b1 + ror(d + m1 + F(b1, b,  c ) + k1)
//	b3 = b2 + ror(c + m2 + F(b2, b1, b ) + k2)
//	b4 = b3 + ror(b + m3 + F(b3, b2, b1) + k3)
//	a, b, c, d = b1, b4, b3, b2
//
// The four F functions and the two message sources also stop being per-step
// decisions: sub-rounds 0-15, 16-31, 32-47 and 48-63 each use one F, and the
// message comes from hiddenG0 below 32 and hiddenG2 above. So the switch and the
// bounds test leave the inner loop as well.
func RoundC_MD5Plain(state *[4]uint32, hiddenG0, hiddenG2 *[16]uint32) {
	a, b, c, d := state[0], state[1], state[2], state[3]

	// Declared up front so the shuffle result does not escape to the heap.
	var g2Buf [16]uint32

	// Group 0: F = d ^ (b & (c^d)), message from hiddenG0.
	for i := 0; i < 16; i += 4 {
		b1 := b + bits.RotateLeft32(a+hiddenG0[MsgSchedule[i]]+(d^(b&(c^d)))+plainAddConsts[i], -int(RorAmounts[i]))
		b2 := b1 + bits.RotateLeft32(d+hiddenG0[MsgSchedule[i+1]]+(c^(b1&(b^c)))+plainAddConsts[i+1], -int(RorAmounts[i+1]))
		b3 := b2 + bits.RotateLeft32(c+hiddenG0[MsgSchedule[i+2]]+(b^(b2&(b1^b)))+plainAddConsts[i+2], -int(RorAmounts[i+2]))
		b4 := b3 + bits.RotateLeft32(b+hiddenG0[MsgSchedule[i+3]]+(b1^(b3&(b2^b1)))+plainAddConsts[i+3], -int(RorAmounts[i+3]))
		a, b, c, d = b1, b4, b3, b2
	}

	// Group 1: F = c ^ (d & (b^c)), message from hiddenG0.
	for i := 16; i < 32; i += 4 {
		b1 := b + bits.RotateLeft32(a+hiddenG0[MsgSchedule[i]]+(c^(d&(b^c)))+plainAddConsts[i], -int(RorAmounts[i]))
		b2 := b1 + bits.RotateLeft32(d+hiddenG0[MsgSchedule[i+1]]+(b^(c&(b1^b)))+plainAddConsts[i+1], -int(RorAmounts[i+1]))
		b3 := b2 + bits.RotateLeft32(c+hiddenG0[MsgSchedule[i+2]]+(b1^(b&(b2^b1)))+plainAddConsts[i+2], -int(RorAmounts[i+2]))
		b4 := b3 + bits.RotateLeft32(b+hiddenG0[MsgSchedule[i+3]]+(b2^(b1&(b3^b2)))+plainAddConsts[i+3], -int(RorAmounts[i+3]))
		a, b, c, d = b1, b4, b3, b2
	}

	// The shuffle sits exactly on the group 1/2 boundary, so it is a step
	// between loops rather than a test inside one. It reads the ENCODED state
	// words: at sub-round 32 the encoding rounds are a:28 b:31 c:30 d:29.
	if hiddenG2 == nil {
		g2Buf = *hiddenG0
		shuffleHiddenG2Into(&g2Buf,
			a^OutBiases[shuffleSubRound-4],
			b^OutBiases[shuffleSubRound-1],
			c^OutBiases[shuffleSubRound-2],
			d^OutBiases[shuffleSubRound-3])
		hiddenG2 = &g2Buf
	}

	// Group 2: F = b ^ c ^ d, message from hiddenG2.
	for i := 32; i < 48; i += 4 {
		b1 := b + bits.RotateLeft32(a+hiddenG2[MsgSchedule[i]]+(b^c^d)+plainAddConsts[i], -int(RorAmounts[i]))
		b2 := b1 + bits.RotateLeft32(d+hiddenG2[MsgSchedule[i+1]]+(b1^b^c)+plainAddConsts[i+1], -int(RorAmounts[i+1]))
		b3 := b2 + bits.RotateLeft32(c+hiddenG2[MsgSchedule[i+2]]+(b2^b1^b)+plainAddConsts[i+2], -int(RorAmounts[i+2]))
		b4 := b3 + bits.RotateLeft32(b+hiddenG2[MsgSchedule[i+3]]+(b3^b2^b1)+plainAddConsts[i+3], -int(RorAmounts[i+3]))
		a, b, c, d = b1, b4, b3, b2
	}

	// Group 3: F = c ^ (b | ^d), message from hiddenG2.
	for i := 48; i < 64; i += 4 {
		b1 := b + bits.RotateLeft32(a+hiddenG2[MsgSchedule[i]]+(c^(b|^d))+plainAddConsts[i], -int(RorAmounts[i]))
		b2 := b1 + bits.RotateLeft32(d+hiddenG2[MsgSchedule[i+1]]+(b^(b1|^c))+plainAddConsts[i+1], -int(RorAmounts[i+1]))
		b3 := b2 + bits.RotateLeft32(c+hiddenG2[MsgSchedule[i+2]]+(b1^(b2|^b))+plainAddConsts[i+2], -int(RorAmounts[i+2]))
		b4 := b3 + bits.RotateLeft32(b+hiddenG2[MsgSchedule[i+3]]+(b2^(b3|^b1))+plainAddConsts[i+3], -int(RorAmounts[i+3]))
		a, b, c, d = b1, b4, b3, b2
	}

	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
}
