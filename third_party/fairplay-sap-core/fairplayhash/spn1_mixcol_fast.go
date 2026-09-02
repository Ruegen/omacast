// SPDX-License-Identifier: BlueOak-1.0.0

package fairplayhash

import "encoding/binary"

// The MixColumns step is a fixed 128x128 GF(2) matrix applied to a 128-bit
// state, so output bit i is the parity of (row_i AND state) plus a constant bit.
// Spelling that out bit by bit costs 16,384 shift-mask-branch iterations per
// call.
//
// Reading it by column instead makes it a sum: each input bit contributes a
// fixed 128-bit column, so a nibble of input contributes the XOR of up to four
// columns. Precomputing those 32x16 combinations turns the whole map into 32
// table lookups. The tables are built at init from the same matrix, so they
// cost nothing in source -- 8 KB of memory, no new constants.
var (
	spn1MixNib   [32][16][2]uint64
	spn1MixConst [2]uint64
)

func init() {
	var cols [128][2]uint64
	for ob := 0; ob < 128; ob++ {
		row := SPN1MixColRows[ob]
		for ib := 0; ib < 128; ib++ {
			if (row[ib>>3]>>(uint(ib)&7))&1 != 0 {
				cols[ib][ob>>6] |= 1 << uint(ob&63)
			}
		}
	}
	for n := 0; n < 32; n++ {
		for v := 0; v < 16; v++ {
			var acc [2]uint64
			for k := 0; k < 4; k++ {
				if v>>uint(k)&1 != 0 {
					c := &cols[n*4+k]
					acc[0] ^= c[0]
					acc[1] ^= c[1]
				}
			}
			spn1MixNib[n][v] = acc
		}
	}
	spn1MixConst[0] = binary.LittleEndian.Uint64(SPN1MixColConst[0:8])
	spn1MixConst[1] = binary.LittleEndian.Uint64(SPN1MixColConst[8:16])
}

func ApplyMixColumns(in [16]byte) [16]byte {
	o0, o1 := spn1MixConst[0], spn1MixConst[1]
	for i := 0; i < 16; i++ {
		b := in[i]
		lo := &spn1MixNib[i*2][b&0xf]
		hi := &spn1MixNib[i*2+1][b>>4]
		o0 ^= lo[0] ^ hi[0]
		o1 ^= lo[1] ^ hi[1]
	}
	var out [16]byte
	binary.LittleEndian.PutUint64(out[0:8], o0)
	binary.LittleEndian.PutUint64(out[8:16], o1)
	return out
}
