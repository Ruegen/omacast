// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "math/bits"

// addConsts are the obfuscated T[i] values for each of the 64 MD5 sub-rounds.
var AddConsts = [64]uint32{
	0x9695377e, 0xa7f24a5c, 0xe34b03e1, 0x80e861f4,
	0xb4a6a2b5, 0x06b25930, 0x675ad919, 0xbc712807,
	0x28ab2bde, 0x4a6f8ab5, 0xbf29eeb7, 0x48876ac4,
	0x2abaa428, 0xbcc30499, 0x65a3d694, 0x08de9b27,
	0xb548b868, 0x86940647, 0xe588ed57, 0xa8e15ab0,
	0x9559a363, 0xc16ea759, 0x97cc7987, 0xa6fe8ece,
	0xe10c60ec, 0x82619adc, 0xb3ffa08d, 0x0484a7f3,
	0x690e7c0b, 0xbc1a36fe, 0x269995df, 0x4c54df90,
	0xbf24cc48, 0x469c8987, 0x2cc7f428, 0xbd0fcb12,
	0x63e97d4a, 0x0b0962af, 0xb5e5de66, 0x7dea4f76,
	0xe7c611cc, 0xa9cbbb00, 0x9419c38b, 0xc3b2b00b,
	0x98ff633f, 0xa6062ceb, 0xdecd0ffe, 0x83d6e96b,
	0xb353b54a, 0x0255929d, 0x6abeb6ad, 0xbbbe333f,
	0x2485ecc9, 0x4e375f98, 0xbf1a8783, 0x44aef0d7,
	0x2ed31155, 0xbd5779e6, 0x622bd61a, 0x0d32a4a7,
	0xb67e1188, 0x7c65853b, 0xea0265c1, 0xaab16697,
}

// modConsts = 2 * outBias for affine bijection reduction.
var ModConsts = [64]uint32{
	0x2b2f55ec, 0x95fdce9c, 0x01453b68, 0x51e49cf4,
	0xd047fc7c, 0x3caf4cd8, 0xbec41846, 0xef33bdda,
	0xa760a0f2, 0x319c88b0, 0xe3ea1d34, 0x3d2fc57a,
	0x996a78e4, 0xf1ae7ffe, 0x81b36544, 0xf3f4d4f0,
	0x7457e6cc, 0x90766eda, 0xd5107492, 0x153cee18,
	0xe85381d0, 0x1a1c97ca, 0xa9be99dc, 0x4daa4ac0,
	0x2b182376, 0x0a0f5b02, 0x54de4fac, 0xcf52d71a,
	0xc0e0fa26, 0xb4dd068c, 0x59be1bd6, 0xc0840c1a,
	0xf638c318, 0x60762ff4, 0x5b34f6d4, 0xcc972894,
	0x17b99e7c, 0x2010cc86, 0x335de7f0, 0x5df74f20,
	0x0c8e30ec, 0xaa0c8aca, 0xdc7bb2e0, 0x468975da,
	0x2d91c95e, 0x19b68850, 0x3fb5b43e, 0x1c14ee5a,
	0x0681f15e, 0x09de60fa, 0xe68baa96, 0xad147952,
	0xc80f6ad8, 0xb746d080, 0xefbf0f80, 0x7f727bb8,
	0x22d0d44a, 0x6d59388c, 0x44075568, 0x3be0faf6,
	0xe4c49252, 0xff6971d6, 0x8d9db6d6, 0x00000000,
}

// outBiases for affine bijection encoding.
var OutBiases = [64]uint32{
	0x1597aaf6, 0x4afee74e, 0x00a29db4, 0x28f24e7a,
	0x6823fe3e, 0x1e57a66c, 0x5f620c23, 0x7799deed,
	0x53b05079, 0x18ce4458, 0x71f50e9a, 0x1e97e2bd,
	0x4cb53c72, 0xf8d73fff, 0x40d9b2a2, 0x79fa6a78,
	0x3a2bf366, 0x483b376d, 0x6a883a49, 0x0a9e770c,
	0x7429c0e8, 0x0d0e4be5, 0x54df4cee, 0x26d52560,
	0x158c11bb, 0x0507ad81, 0x2a6f27d6, 0x67a96b8d,
	0x60707d13, 0x5a6e8346, 0x2cdf0deb, 0x6042060d,
	0x7b1c618c, 0x303b17fa, 0x2d9a7b6a, 0x664b944a,
	0x0bdccf3e, 0x10086643, 0x19aef3f8, 0x2efba790,
	0x06471876, 0x55064565, 0x6e3dd970, 0x2344baed,
	0x16c8e4af, 0x0cdb4428, 0x1fdada1f, 0x0e0a772d,
	0x0340f8af, 0x04ef307d, 0x7345d54b, 0x568a3ca9,
	0x6407b56c, 0x5ba36840, 0x77df87c0, 0x3fb93ddc,
	0x11686a25, 0x36ac9c46, 0x2203aab4, 0x1df07d7b,
	0x72624929, 0x7fb4b8eb, 0x46cedb6b, 0x00000000,
}

// MD5 rotation amounts (right-rotate = 32 - left_rotate).
var RorAmounts = [64]uint{
	25, 20, 15, 10, 25, 20, 15, 10,
	25, 20, 15, 10, 25, 20, 15, 10,
	27, 23, 18, 12, 27, 23, 18, 12,
	27, 23, 18, 12, 27, 23, 18, 12,
	28, 21, 16, 9, 28, 21, 16, 9,
	28, 21, 16, 9, 28, 21, 16, 9,
	26, 22, 17, 11, 26, 22, 17, 11,
	26, 22, 17, 11, 26, 22, 17, 11,
}

// MsgSchedule is the standard MD5 message word schedule.
// All 4 groups use standard MD5 indexing, verified against ARM64 instruction
// stream extraction (LDR [SP, #offset] patterns match standard k formulas):
//
//	Group 0 (F): k = i
//	Group 1 (G): k = (5i + 1) mod 16
//	Group 2 (H): k = (3i + 5) mod 16
//	Group 3 (I): k = (7i) mod 16
//
// The WB-MD5 applies a state-dependent hidden-word permutation at the
// Group 1→2 boundary, but the schedule indices themselves are standard.
var MsgSchedule = [64]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
}

// roundC_WBMD5 performs one round of White-Box MD5 with affine bijection encoding.
// state contains the 4 MD5 state words (a, b, c, d).
// msg contains the 16 message words (hidden constants from the WB implementation).
//
// The bijection is XOR-based (modConst = 2*outBias → f(x) = x ^ outBias).
// State words are encoded via XOR with outBias after each round's bijection step.
// Round 17 has an anomalous extra outBias[encRound_of_a] correction.
// This is the canonical form matching the ARM64 implementation.
func RoundC_WBMD5_Permuted(state *[4]uint32, hiddenG0, hiddenG2 *[16]uint32) {
	a, b, c, d := state[0], state[1], state[2], state[3]
	aEnc, bEnc, cEnc, dEnc := -1, -1, -1, -1

	for i := 0; i < 64; i++ {
		// At the Group 1→2 boundary, compute G2 hidden words from the
		// encoded state using the state-dependent Fisher-Yates shuffle.
		// This must happen before SR 32 accesses hiddenG2.
		if i == 32 && hiddenG2 == nil {
			g2 := ShuffleHiddenG2(hiddenG0, a, b, c, d)
			hiddenG2 = &g2
		}

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

		var msg uint32
		if i < 32 {
			msg = hiddenG0[MsgSchedule[i]]
		} else {
			msg = hiddenG2[MsgSchedule[i]]
		}

		aFull := aDec + msg
		if i == 17 && aEnc >= 0 {
			aFull += OutBiases[aEnc]
		}
		tmp := aFull + f + AddConsts[i]

		tmp = bits.RotateLeft32(tmp, -int(RorAmounts[i]))
		postAddB := tmp + bDec
		newB := postAddB - (ModConsts[i] & (postAddB << 1)) + OutBiases[i]

		a, b, c, d = d, newB, b, c
		aEnc, bEnc, cEnc, dEnc = dEnc, i, bEnc, cEnc
	}

	// Decode before accumulation
	if aEnc >= 0 {
		a ^= OutBiases[aEnc]
	}
	if bEnc >= 0 {
		b ^= OutBiases[bEnc]
	}
	if cEnc >= 0 {
		c ^= OutBiases[cEnc]
	}
	if dEnc >= 0 {
		d ^= OutBiases[dEnc]
	}

	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
}
