// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "encoding/binary"

// Rounds 8 and 19 of the WB-MD5 loop get their hidden words from a white-box AES
// SPN output, not from the normal NEON prologue. Both build a 64-byte MD5
// message and run it through the same 4x neonBlock (no round counter), then the
// state-dependent G2 shuffle (hiddenG2 = nil). This is the mechanism that makes
// R8/R19 payload-dependent -- the blocker open since the first handoff, now
// closed because SPN#1 (which feeds R8) is fully solved.
//
//   R8 staging  = [ bswap(SPN1 output)     ‖ r8Data1Const ‖ 0x80-pad ‖ len=256 ]
//   R19 staging = [ LittleEndian(roundOutputs[8]) ‖ bswap(TailSPN output) ‖ pad ‖ len ]

// r8Data1Const is R8's second message block (payload-independent), followed by
// the shared MD5 pad+length (0x80 then zeros then the 256-bit length).
var r8Suffix = [48]byte{
	0xa0, 0x2b, 0xc2, 0xaf, 0xfb, 0xfc, 0xef, 0x49, 0x5e, 0xac, 0x67, 0xfe, 0xcb, 0xfb, 0xf6, 0xbe,
	0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// mdPadLen is the MD5 pad+length tail shared by R8 and R19 (bytes 32..63).
var mdPadLen = [32]byte{
	0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// hiddenFromStaging runs the 4x neonBlock (no counter) over a 64-byte staging
// message, producing the 16 G0 hidden words.
func hiddenFromStaging(src [64]byte) [16]uint32 {
	xorMask := dup32(NeonXORConst)
	andMask := dup32(NeonANDConst)
	addBias := dup32(NeonADDConst)
	var h [16]uint32
	for b := 0; b < 4; b++ {
		lo := binary.LittleEndian.Uint64(src[b*16:])
		hi := binary.LittleEndian.Uint64(src[b*16+8:])
		h0, h1, h2, h3 := neonBlock(lo, hi, xorMask, andMask, addBias)
		h[b*4+0], h[b*4+1], h[b*4+2], h[b*4+3] = h0, h1, h2, h3
	}
	return h
}

func bswapWords16(in [16]byte) (o [16]byte) {
	for w := 0; w < 4; w++ {
		o[w*4+0], o[w*4+1], o[w*4+2], o[w*4+3] = in[w*4+3], in[w*4+2], in[w*4+1], in[w*4+0]
	}
	return
}

// R8Staging builds round 8's 64-byte MD5 message from SPN#1's 16-byte output.
func R8Staging(spn1Out [16]byte) (src [64]byte) {
	d0 := bswapWords16(spn1Out)
	copy(src[0:16], d0[:])
	copy(src[16:64], r8Suffix[:])
	return
}

// R8HiddenWords derives round 8's G0 hidden words from SPN#1's output.
func R8HiddenWords(spn1Out [16]byte) [16]uint32 {
	return hiddenFromStaging(R8Staging(spn1Out))
}

// R19Staging builds round 19's 64-byte MD5 message from roundOutputs[8] and the
// TailSPN output. data0 = LittleEndian(ro8); data1 = bswap(tailSPNOut).
func R19Staging(ro8 [4]uint32, tailSPNOut [16]byte) (src [64]byte) {
	for w := 0; w < 4; w++ {
		binary.LittleEndian.PutUint32(src[w*4:], ro8[w])
	}
	d1 := bswapWords16(tailSPNOut)
	copy(src[16:32], d1[:])
	copy(src[32:64], mdPadLen[:])
	return
}
