// SPDX-License-Identifier: LGPL-3.0-or-later
// Derived from github.com/omarroth/doubletake at 8ccea5f. See ../NOTICE.md.

package fpsapcore

import (
	"encoding/binary"
	"math/bits"
)

// fairplayMD5Compress is the round loop with the state rotation removed, the
// same way fairplayhash.RoundC_MD5Plain is: each round ends with
// a, b, c, d = d, b+rotl(...), b, c, which is four register moves that exist
// only to renumber. Unrolling by four does the renumbering in the naming, so a
// round computes one value and moves nothing. From (a, b, c, d):
//
//	b1 = b  + rotl(a + F(b,  c,  d ) + K + M)
//	b2 = b1 + rotl(d + F(b1, b,  c ) + K + M)
//	b3 = b2 + rotl(c + F(b2, b1, b ) + K + M)
//	b4 = b3 + rotl(b + F(b3, b2, b1) + K + M)
//	a, b, c, d = b1, b4, b3, b2
//
// The F selector leaves the loop too, since each group of sixteen uses one F.
// The message mutation happens after round 31, exactly on the group 1/2
// boundary, so it becomes a step between loops rather than a test inside one.
func fairplayMD5Compress(state [4]uint32, block []byte, mutation fairplayMD5Mutation) [4]uint32 {
	var m [16]uint32
	for i := range m {
		m[i] = binary.BigEndian.Uint32(block[i*4:])
	}

	a, b, c, d := state[0], state[1], state[2], state[3]

	// Group 0: F = (B&C)|(^B&D), word = round.
	for i := 0; i < 16; i += 4 {
		b1 := b + bits.RotateLeft32(a+((b&c)|(^b&d))+fairplayMD5Constant[i]+m[i], fairplayMD5Shift[i])
		b2 := b1 + bits.RotateLeft32(d+((b1&b)|(^b1&c))+fairplayMD5Constant[i+1]+m[i+1], fairplayMD5Shift[i+1])
		b3 := b2 + bits.RotateLeft32(c+((b2&b1)|(^b2&b))+fairplayMD5Constant[i+2]+m[i+2], fairplayMD5Shift[i+2])
		b4 := b3 + bits.RotateLeft32(b+((b3&b2)|(^b3&b1))+fairplayMD5Constant[i+3]+m[i+3], fairplayMD5Shift[i+3])
		a, b, c, d = b1, b4, b3, b2
	}

	// Group 1: F = (D&B)|(^D&C), word = (5*round+1)&15.
	for i := 16; i < 32; i += 4 {
		b1 := b + bits.RotateLeft32(a+((d&b)|(^d&c))+fairplayMD5Constant[i]+m[(5*i+1)&15], fairplayMD5Shift[i])
		b2 := b1 + bits.RotateLeft32(d+((c&b1)|(^c&b))+fairplayMD5Constant[i+1]+m[(5*(i+1)+1)&15], fairplayMD5Shift[i+1])
		b3 := b2 + bits.RotateLeft32(c+((b&b2)|(^b&b1))+fairplayMD5Constant[i+2]+m[(5*(i+2)+1)&15], fairplayMD5Shift[i+2])
		b4 := b3 + bits.RotateLeft32(b+((b1&b3)|(^b1&b2))+fairplayMD5Constant[i+3]+m[(5*(i+3)+1)&15], fairplayMD5Shift[i+3])
		a, b, c, d = b1, b4, b3, b2
	}

	mutateFairplayMD5Message(&m, a, b, c, d, mutation)

	// Group 2: F = B^C^D, word = (3*round+5)&15.
	for i := 32; i < 48; i += 4 {
		b1 := b + bits.RotateLeft32(a+(b^c^d)+fairplayMD5Constant[i]+m[(3*i+5)&15], fairplayMD5Shift[i])
		b2 := b1 + bits.RotateLeft32(d+(b1^b^c)+fairplayMD5Constant[i+1]+m[(3*(i+1)+5)&15], fairplayMD5Shift[i+1])
		b3 := b2 + bits.RotateLeft32(c+(b2^b1^b)+fairplayMD5Constant[i+2]+m[(3*(i+2)+5)&15], fairplayMD5Shift[i+2])
		b4 := b3 + bits.RotateLeft32(b+(b3^b2^b1)+fairplayMD5Constant[i+3]+m[(3*(i+3)+5)&15], fairplayMD5Shift[i+3])
		a, b, c, d = b1, b4, b3, b2
	}

	// Group 3: F = C^(B|^D), word = (7*round)&15.
	for i := 48; i < 64; i += 4 {
		b1 := b + bits.RotateLeft32(a+(c^(b|^d))+fairplayMD5Constant[i]+m[(7*i)&15], fairplayMD5Shift[i])
		b2 := b1 + bits.RotateLeft32(d+(b^(b1|^c))+fairplayMD5Constant[i+1]+m[(7*(i+1))&15], fairplayMD5Shift[i+1])
		b3 := b2 + bits.RotateLeft32(c+(b1^(b2|^b))+fairplayMD5Constant[i+2]+m[(7*(i+2))&15], fairplayMD5Shift[i+2])
		b4 := b3 + bits.RotateLeft32(b+(b2^(b3|^b1))+fairplayMD5Constant[i+3]+m[(7*(i+3))&15], fairplayMD5Shift[i+3])
		a, b, c, d = b1, b4, b3, b2
	}

	return [4]uint32{state[0] + a, state[1] + b, state[2] + c, state[3] + d}
}
