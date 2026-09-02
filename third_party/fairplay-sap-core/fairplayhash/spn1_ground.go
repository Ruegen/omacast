// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

// TailInput computes the input to the tail white-box AES SPN (TailSPN) fully
// analytically. It is a fixed final AES round applied to BE(roundOutputs[8]):
// per output position a single S-box lookup (fan-in 1, ShiftRows-style
// permutation) XORed with the 9th mixTable block, which is BE(roundOutputs[18]).
//
//	tail_input[p] = gSbox[p][ BE(ro8)[gPerm[p]] ] ^ BE(ro18)[p]
//
// The result feeds TailSPN; bswap(TailSPN(tail_input, mixTable)) is round 19's
// hidden-words data1 (see spn1_r8r19.go / R19Staging).
func TailInput(roundOutputs *[20][4]uint32) [16]byte {
	be8 := beRoundOutput(roundOutputs[8])
	be18 := beRoundOutput(roundOutputs[18])
	var out [16]byte
	for p := 0; p < 16; p++ {
		out[p] = gSbox[p][be8[gPerm[p]]] ^ be18[p]
	}
	return out
}
